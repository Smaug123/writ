//! Example-based tests for the per-commit upload walker
//! (`replay_commits`) and its `ShaMap` accounting.

use super::test_fixture::InMemoryGitObjectSource;
use super::test_support::*;
use super::*;
use crate::git_push_replay::TrailerKey;
use serde_json::json;
use wiremock::MockServer;

// ----- ShaMap -----

#[test]
fn sha_map_seeds_commit_identity_mapping() {
    let mut map = ShaMap::new();
    let sha = sample_object_id('a');
    map.seed_commit_identity(sha.clone());
    assert_eq!(map.commit(&sha), Some(&sha));
    assert_eq!(map.commit_count(), 1);
    assert_eq!(map.blob_count(), 0);
    assert_eq!(map.tree_count(), 0);
}

// ----- walker -----

/// A single bundle commit with no parents, an empty tree, and
/// no body. Verifies the minimum wire shape end-to-end.
#[tokio::test]
async fn replay_uploads_single_initial_commit_with_empty_tree() {
    let server = MockServer::start().await;
    let commit_sha = sample_object_id('1');
    let tree_sha = sample_object_id('2');

    let app_tree_sha = sample_object_id('a');
    let app_commit_sha = sample_object_id('b');

    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(tree_sha.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        commit_sha.clone(),
        StagingCommit {
            tree: tree_sha.clone(),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bot"),
            message: "initial\n".to_string(),
        },
    );

    mount_tree_create(&server, json!({ "tree": [] }), &app_tree_sha).await;
    mount_commit_create(
        &server,
        json!({
            "message": "initial\n",
            "tree": app_tree_sha.as_str(),
            "parents": [],
            "author": {
                "name": "Alice",
                "email": "Alice@example.invalid",
                "date": "2024-01-15T10:30:45Z",
            },
            "committer": {
                "name": "Bot",
                "email": "Bot@example.invalid",
                "date": "2024-01-15T10:30:45Z",
            },
        }),
        &app_commit_sha,
    )
    .await;

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        std::slice::from_ref(&commit_sha),
        ShaMap::new(),
        &[],
        None,
    )
    .await
    .expect("walker ok");

    assert_eq!(final_sha, app_commit_sha);
    assert_eq!(map.commit(&commit_sha), Some(&app_commit_sha));
    assert_eq!(map.tree(&tree_sha), Some(&app_tree_sha));
    assert_eq!(map.commit_count(), 1);
    assert_eq!(map.tree_count(), 1);
    assert_eq!(map.blob_count(), 0);
}

/// Three commits in a chain: c0 -> c1 -> c2. Each modifies a
/// single file. Verifies that:
///   * the seed commit is not re-uploaded (c0's parent equals
///     the seed),
///   * each commit's parent in the wire body is the *App-side*
///     SHA of the previous commit,
///   * the blob and tree maps grow once per new object.
#[tokio::test]
async fn replay_walks_linear_chain_and_remaps_parents() {
    let server = MockServer::start().await;
    let upstream = sample_object_id('0');

    let blob_bundle = [sample_object_id('1'), sample_object_id('2')];
    let blob_content: [&[u8]; 2] = [b"alpha\n", b"beta\n"];
    let blob_app = [sample_object_id('a'), sample_object_id('b')];

    let tree_bundle = [sample_object_id('3'), sample_object_id('4')];
    let tree_app = [sample_object_id('c'), sample_object_id('d')];

    let commit_bundle = [sample_object_id('5'), sample_object_id('6')];
    let commit_app = [sample_object_id('e'), sample_object_id('f')];

    let mut source = InMemoryGitObjectSource::new();
    for (i, content) in blob_content.iter().enumerate() {
        source.insert_blob(blob_bundle[i].clone(), content.to_vec());
        mount_blob_create(&server, content, &blob_app[i]).await;
    }

    for (i, tree_sha) in tree_bundle.iter().enumerate() {
        source.insert_tree(
            tree_sha.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "file.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: blob_bundle[i].clone(),
                }],
            },
        );
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "file.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_app[i].as_str(),
                }],
            }),
            &tree_app[i],
        )
        .await;
    }

    let parents_pattern = [vec![upstream.clone()], vec![commit_bundle[0].clone()]];
    let parents_app = [vec![upstream.clone()], vec![commit_app[0].clone()]];
    for (i, commit_sha) in commit_bundle.iter().enumerate() {
        source.insert_commit(
            commit_sha.clone(),
            StagingCommit {
                tree: tree_bundle[i].clone(),
                parents: parents_pattern[i].clone(),
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: format!("commit {i}\n"),
            },
        );
        let parents_json: Vec<&str> = parents_app[i].iter().map(GitObjectId::as_str).collect();
        mount_commit_create(
            &server,
            json!({
                "message": format!("commit {i}\n"),
                "tree": tree_app[i].as_str(),
                "parents": parents_json,
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Bot",
                    "email": "Bot@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            }),
            &commit_app[i],
        )
        .await;
    }

    let mut seed = ShaMap::new();
    seed.seed_commit_identity(upstream.clone());

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &commit_bundle,
        seed,
        &[],
        None,
    )
    .await
    .expect("walker ok");

    assert_eq!(final_sha, commit_app[1]);
    assert_eq!(map.commit_count(), 3); // upstream + 2 replayed
    assert_eq!(map.tree_count(), 2);
    assert_eq!(map.blob_count(), 2);
    // Upstream stays as identity.
    assert_eq!(map.commit(&upstream), Some(&upstream));
}

/// A merge commit with two parents, both of which appear earlier
/// in the topo-sorted list. Verifies that the wire body's
/// `parents` array preserves order and uses both remapped SHAs.
#[tokio::test]
async fn replay_handles_merge_commit_with_two_parents() {
    let server = MockServer::start().await;
    let upstream = sample_object_id('0');

    // Topology:
    //
    //   upstream → c_left
    //            ↘
    //              merge
    //            ↗
    //   upstream → c_right
    let blob_left_bundle = sample_object_id('1');
    let blob_right_bundle = sample_object_id('2');
    let blob_merge_bundle = sample_object_id('3');
    let blob_left_app = sample_object_id('a');
    let blob_right_app = sample_object_id('b');
    let blob_merge_app = sample_object_id('c');

    let tree_left_bundle = sample_object_id('4');
    let tree_right_bundle = sample_object_id('5');
    let tree_merge_bundle = sample_object_id('6');
    let tree_left_app = sample_object_id('d');
    let tree_right_app = sample_object_id('e');
    let tree_merge_app = sample_object_id('f');

    let commit_left_bundle = sample_object_id('7');
    let commit_right_bundle = sample_object_id('8');
    let commit_merge_bundle = sample_object_id('9');
    // Use distinct repeated-nibble SHAs that don't collide with any
    // of the bundle ones above.
    let commit_left_app =
        GitObjectId::new("abababababababababababababababababababab".to_string()).unwrap();
    let commit_right_app =
        GitObjectId::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string()).unwrap();
    let commit_merge_app =
        GitObjectId::new("efefefefefefefefefefefefefefefefefefefef".to_string()).unwrap();

    let mut source = InMemoryGitObjectSource::new();
    source.insert_blob(blob_left_bundle.clone(), b"left\n".to_vec());
    source.insert_blob(blob_right_bundle.clone(), b"right\n".to_vec());
    source.insert_blob(blob_merge_bundle.clone(), b"merged\n".to_vec());
    mount_blob_create(&server, b"left\n", &blob_left_app).await;
    mount_blob_create(&server, b"right\n", &blob_right_app).await;
    mount_blob_create(&server, b"merged\n", &blob_merge_app).await;

    source.insert_tree(
        tree_left_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "f.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: blob_left_bundle.clone(),
            }],
        },
    );
    source.insert_tree(
        tree_right_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "f.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: blob_right_bundle.clone(),
            }],
        },
    );
    source.insert_tree(
        tree_merge_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "f.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: blob_merge_bundle.clone(),
            }],
        },
    );
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "f.txt",
                "mode": "100644",
                "type": "blob",
                "sha": blob_left_app.as_str(),
            }],
        }),
        &tree_left_app,
    )
    .await;
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "f.txt",
                "mode": "100644",
                "type": "blob",
                "sha": blob_right_app.as_str(),
            }],
        }),
        &tree_right_app,
    )
    .await;
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "f.txt",
                "mode": "100644",
                "type": "blob",
                "sha": blob_merge_app.as_str(),
            }],
        }),
        &tree_merge_app,
    )
    .await;

    source.insert_commit(
        commit_left_bundle.clone(),
        StagingCommit {
            tree: tree_left_bundle.clone(),
            parents: vec![upstream.clone()],
            author: sample_identity("L"),
            committer: sample_identity("Bot"),
            message: "left side\n".to_string(),
        },
    );
    source.insert_commit(
        commit_right_bundle.clone(),
        StagingCommit {
            tree: tree_right_bundle.clone(),
            parents: vec![upstream.clone()],
            author: sample_identity("R"),
            committer: sample_identity("Bot"),
            message: "right side\n".to_string(),
        },
    );
    source.insert_commit(
        commit_merge_bundle.clone(),
        StagingCommit {
            tree: tree_merge_bundle.clone(),
            parents: vec![commit_left_bundle.clone(), commit_right_bundle.clone()],
            author: sample_identity("M"),
            committer: sample_identity("Bot"),
            message: "merge\n".to_string(),
        },
    );

    mount_commit_create(
            &server,
            json!({
                "message": "left side\n",
                "tree": tree_left_app.as_str(),
                "parents": [upstream.as_str()],
                "author": { "name": "L", "email": "L@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_left_app,
        )
        .await;
    mount_commit_create(
            &server,
            json!({
                "message": "right side\n",
                "tree": tree_right_app.as_str(),
                "parents": [upstream.as_str()],
                "author": { "name": "R", "email": "R@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_right_app,
        )
        .await;
    mount_commit_create(
            &server,
            json!({
                "message": "merge\n",
                "tree": tree_merge_app.as_str(),
                "parents": [commit_left_app.as_str(), commit_right_app.as_str()],
                "author": { "name": "M", "email": "M@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_merge_app,
        )
        .await;

    let mut seed = ShaMap::new();
    seed.seed_commit_identity(upstream.clone());

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &[
            commit_left_bundle.clone(),
            commit_right_bundle.clone(),
            commit_merge_bundle.clone(),
        ],
        seed,
        &[],
        None,
    )
    .await
    .expect("walker ok");

    assert_eq!(final_sha, commit_merge_app);
    assert_eq!(map.commit_count(), 4); // upstream + left + right + merge
    assert_eq!(map.tree_count(), 3);
    assert_eq!(map.blob_count(), 3);
}

/// Two commits share an identical blob via two separate paths.
/// The blob must be uploaded exactly once and both trees should
/// reference the same App-side blob SHA.
#[tokio::test]
async fn replay_uploads_each_unique_blob_exactly_once() {
    let server = MockServer::start().await;

    let shared_bundle = sample_object_id('1');
    let shared_app = sample_object_id('a');
    let shared_content: &[u8] = b"shared content\n";
    // `.expect(1)` on the mock means a second upload would
    // surface as an unmatched request.
    mount_blob_create(&server, shared_content, &shared_app).await;

    let tree_a_bundle = sample_object_id('2');
    let tree_b_bundle = sample_object_id('3');
    let tree_a_app = sample_object_id('b');
    let tree_b_app = sample_object_id('c');
    let mut source = InMemoryGitObjectSource::new();
    source.insert_blob(shared_bundle.clone(), shared_content.to_vec());
    source.insert_tree(
        tree_a_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "a.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: shared_bundle.clone(),
            }],
        },
    );
    source.insert_tree(
        tree_b_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "b.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: shared_bundle.clone(),
            }],
        },
    );
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "a.txt",
                "mode": "100644",
                "type": "blob",
                "sha": shared_app.as_str(),
            }],
        }),
        &tree_a_app,
    )
    .await;
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "b.txt",
                "mode": "100644",
                "type": "blob",
                "sha": shared_app.as_str(),
            }],
        }),
        &tree_b_app,
    )
    .await;

    let commit_a_bundle = sample_object_id('4');
    let commit_b_bundle = sample_object_id('5');
    let commit_a_app = sample_object_id('d');
    let commit_b_app = sample_object_id('e');
    source.insert_commit(
        commit_a_bundle.clone(),
        StagingCommit {
            tree: tree_a_bundle.clone(),
            parents: vec![],
            author: sample_identity("A"),
            committer: sample_identity("Bot"),
            message: "a\n".to_string(),
        },
    );
    source.insert_commit(
        commit_b_bundle.clone(),
        StagingCommit {
            tree: tree_b_bundle.clone(),
            parents: vec![commit_a_bundle.clone()],
            author: sample_identity("B"),
            committer: sample_identity("Bot"),
            message: "b\n".to_string(),
        },
    );
    mount_commit_create(
            &server,
            json!({
                "message": "a\n",
                "tree": tree_a_app.as_str(),
                "parents": [],
                "author": { "name": "A", "email": "A@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_a_app,
        )
        .await;
    mount_commit_create(
            &server,
            json!({
                "message": "b\n",
                "tree": tree_b_app.as_str(),
                "parents": [commit_a_app.as_str()],
                "author": { "name": "B", "email": "B@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_b_app,
        )
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &[commit_a_bundle.clone(), commit_b_bundle.clone()],
        ShaMap::new(),
        &[],
        None,
    )
    .await
    .expect("walker ok");

    assert_eq!(final_sha, commit_b_app);
    assert_eq!(map.blob_count(), 1);
    assert_eq!(map.blob(&shared_bundle), Some(&shared_app));
}

/// A subtree (sub-directory) inside the root tree. Walker uploads
/// the subtree first, then the root with the remapped subtree
/// SHA.
#[tokio::test]
async fn replay_walks_nested_subtree_in_post_order() {
    let server = MockServer::start().await;
    let blob_bundle = sample_object_id('1');
    let blob_app = sample_object_id('a');
    mount_blob_create(&server, b"deep\n", &blob_app).await;

    let subtree_bundle = sample_object_id('2');
    let subtree_app = sample_object_id('b');
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "leaf.txt",
                "mode": "100644",
                "type": "blob",
                "sha": blob_app.as_str(),
            }],
        }),
        &subtree_app,
    )
    .await;

    let root_bundle = sample_object_id('3');
    let root_app = sample_object_id('c');
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "sub",
                "mode": "040000",
                "type": "tree",
                "sha": subtree_app.as_str(),
            }],
        }),
        &root_app,
    )
    .await;

    let commit_bundle = sample_object_id('4');
    let commit_app = sample_object_id('d');
    let mut source = InMemoryGitObjectSource::new();
    source.insert_blob(blob_bundle.clone(), b"deep\n".to_vec());
    source.insert_tree(
        subtree_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "leaf.txt".to_string(),
                kind: TreeEntryKind::Blob,
                sha: blob_bundle.clone(),
            }],
        },
    );
    source.insert_tree(
        root_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "sub".to_string(),
                kind: TreeEntryKind::Subtree,
                sha: subtree_bundle.clone(),
            }],
        },
    );
    source.insert_commit(
        commit_bundle.clone(),
        StagingCommit {
            tree: root_bundle.clone(),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bot"),
            message: "deep\n".to_string(),
        },
    );

    mount_commit_create(
            &server,
            json!({
                "message": "deep\n",
                "tree": root_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
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

    assert_eq!(final_sha, commit_app);
    assert_eq!(map.tree(&subtree_bundle), Some(&subtree_app));
    assert_eq!(map.tree(&root_bundle), Some(&root_app));
    assert_eq!(map.tree_count(), 2);
}

/// The walker appends a `Replay-from` trailer naming the bundle
/// commit's own SHA. Verified by strict body match against the
/// commit create endpoint.
#[tokio::test]
async fn replay_appends_trailers_to_commit_message() {
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
            message: "subject\n\nbody\n".to_string(),
        },
    );

    mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

    let expected_message = format!(
        "subject\n\nbody\n\nReplay-from: {}\n",
        commit_bundle.as_str()
    );
    mount_commit_create(
            &server,
            json!({
                "message": expected_message,
                "tree": tree_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

    let trailers = [TrailerSource::OriginalCommitSha {
        key: TrailerKey::new("Replay-from").unwrap(),
    }];
    let client = client_against(&server, "ghs_fake_token");
    let (_, _) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &[commit_bundle],
        ShaMap::new(),
        &trailers,
        None,
    )
    .await
    .expect("walker ok");
}

/// A bundle commit names a parent that is in neither the seed
/// nor the topo-sorted commit list. Walker surfaces this as
/// [`ReplayError::UnmappedParent`] without silently emitting an
/// orphan commit.
#[tokio::test]
async fn replay_reports_unmapped_parent_without_uploading_commit() {
    let server = MockServer::start().await;
    // The walker is going to read the tree and upload it before
    // it inspects the commit's parents. Mount that one
    // response; if the walker tries to call create_commit
    // anyway, wiremock will surface it as unmatched.
    let commit_bundle = sample_object_id('1');
    let tree_bundle = sample_object_id('2');
    let tree_app = sample_object_id('a');
    let orphan_parent = sample_object_id('9');

    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        commit_bundle.clone(),
        StagingCommit {
            tree: tree_bundle.clone(),
            parents: vec![orphan_parent.clone()],
            author: sample_identity("Alice"),
            committer: sample_identity("Bot"),
            message: "lone\n".to_string(),
        },
    );
    mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

    let client = client_against(&server, "ghs_fake_token");
    let err = replay_commits(
        &client,
        &sample_repo(),
        &source,
        std::slice::from_ref(&commit_bundle),
        ShaMap::new(),
        &[],
        None,
    )
    .await
    .expect_err("unmapped parent must abort the walk");
    match err {
        ReplayError::UnmappedParent {
            bundle_sha,
            parent_sha,
        } => {
            assert_eq!(bundle_sha, commit_bundle.as_str());
            assert_eq!(parent_sha, orphan_parent.as_str());
        }
        other => panic!("expected UnmappedParent, got {other:?}"),
    }
}

/// A submodule entry names a commit in a different repository.
/// The walker must pass the SHA through verbatim — *not* try to
/// upload it as a commit on the current repo.
#[tokio::test]
async fn replay_passes_submodule_commit_sha_through_unchanged() {
    let server = MockServer::start().await;
    // Submodule SHA: not in the in-memory source's commit map.
    // If the walker mistakenly tried to read it, the test would
    // fail with a NotFound source error.
    let submodule_sha = sample_object_id('9');
    let root_bundle = sample_object_id('1');
    let root_app = sample_object_id('a');
    mount_tree_create(
        &server,
        json!({
            "tree": [{
                "path": "vendored",
                "mode": "160000",
                "type": "commit",
                "sha": submodule_sha.as_str(),
            }],
        }),
        &root_app,
    )
    .await;

    let commit_bundle = sample_object_id('2');
    let commit_app = sample_object_id('b');
    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(
        root_bundle.clone(),
        StagingTree {
            entries: vec![StagingTreeEntry {
                path: "vendored".to_string(),
                kind: TreeEntryKind::Submodule,
                sha: submodule_sha.clone(),
            }],
        },
    );
    source.insert_commit(
        commit_bundle.clone(),
        StagingCommit {
            tree: root_bundle.clone(),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bot"),
            message: "vendored\n".to_string(),
        },
    );

    mount_commit_create(
            &server,
            json!({
                "message": "vendored\n",
                "tree": root_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        std::slice::from_ref(&commit_bundle),
        ShaMap::new(),
        &[],
        None,
    )
    .await
    .expect("walker handles submodule entries");

    assert_eq!(final_sha, commit_app);
    // No blob upload happened for the submodule SHA.
    assert_eq!(map.blob_count(), 0);
    // The submodule SHA does not appear in the commit map either
    // — we don't claim to have replayed it on this repo.
    assert_eq!(map.commit(&submodule_sha), None);
}
