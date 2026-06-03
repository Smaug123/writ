//! `ListStagedPushes` / `ShowStagedPush` read-path tests.

use super::test_support::*;
use super::*;
use wiremock::MockServer;

#[tokio::test]
async fn list_staged_pushes_without_staging_configured_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("staging"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Same staging-absent error path on the filtered request: the
/// session_id filter must not change *which* errors the broker
/// returns, only which entries it keeps on the success path.
#[tokio::test]
async fn list_staged_pushes_with_session_filter_without_staging_configured_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(SessionId::new()),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("staging"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn list_staged_pushes_with_empty_store_returns_empty_list() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let resp = dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
    assert_eq!(resp, ServerMessage::StagedPushes { pushes: vec![] });
}

#[tokio::test]
async fn list_staged_pushes_returns_summary_for_each_staged_entry() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;

    let id_a = stage_with_audit(
        &state,
        session_id,
        b"bundle-a".to_vec(),
        UnixMillis::from_millis(1_700_000_001_000),
        UnixMillis::from_millis(1_700_000_001_500),
    )
    .await;
    let id_b = stage_with_audit(
        &state,
        session_id,
        b"bundle-b".to_vec(),
        UnixMillis::from_millis(1_700_000_002_000),
        UnixMillis::from_millis(1_700_000_002_500),
    )
    .await;

    let resp = dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
    let mut pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    pushes.sort_by_key(|p| p.staged_at);
    assert_eq!(pushes.len(), 2);
    assert_eq!(pushes[0].push_request_id, id_a);
    assert_eq!(pushes[0].staged_at.as_millis(), 1_700_000_001_000);
    assert_eq!(pushes[1].push_request_id, id_b);
    assert_eq!(pushes[1].staged_at.as_millis(), 1_700_000_002_000);
}

/// Filtering by `session_id` returns only the staged pushes recorded
/// under that session in the audit log. Witnesses the core join:
/// pushes from a sibling session never appear in the result.
#[tokio::test]
async fn list_staged_pushes_with_session_filter_returns_only_matching_pushes() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_a = open_session(&state).await;
    let session_b = open_session(&state).await;

    let id_a1 = stage_with_audit(
        &state,
        session_a,
        b"a1".to_vec(),
        UnixMillis::from_millis(1_700_000_001_000),
        UnixMillis::from_millis(1_700_000_001_500),
    )
    .await;
    let id_a2 = stage_with_audit(
        &state,
        session_a,
        b"a2".to_vec(),
        UnixMillis::from_millis(1_700_000_002_000),
        UnixMillis::from_millis(1_700_000_002_500),
    )
    .await;
    let id_b1 = stage_with_audit(
        &state,
        session_b,
        b"b1".to_vec(),
        UnixMillis::from_millis(1_700_000_003_000),
        UnixMillis::from_millis(1_700_000_003_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(session_a),
        },
        &state,
    )
    .await;
    let mut pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    pushes.sort_by_key(|p| p.staged_at);
    assert_eq!(pushes.len(), 2);
    assert_eq!(pushes[0].push_request_id, id_a1);
    assert_eq!(pushes[1].push_request_id, id_a2);

    // Sibling session sees only its own push, not session_a's two.
    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(session_b),
        },
        &state,
    )
    .await;
    let pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].push_request_id, id_b1);

    // And the unfiltered listing still returns all three: filtering
    // is an opt-in narrowing, not a hidden default.
    let resp = dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
    let pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    assert_eq!(pushes.len(), 3);
}

/// Filter by a session that has no push rows in the audit log
/// (e.g. a session that was opened but never staged a push, or an
/// id that does not exist at all). The broker returns an empty
/// list rather than an error: "no rows matched the filter" is a
/// successful empty listing.
#[tokio::test]
async fn list_staged_pushes_with_session_filter_for_unknown_session_returns_empty() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);

    // Seed the staging store with one push under a different
    // session so we can witness it is excluded by the unknown-
    // session filter.
    let other = open_session(&state).await;
    stage_with_audit(
        &state,
        other,
        b"other".to_vec(),
        UnixMillis::from_millis(1_700_000_001_000),
        UnixMillis::from_millis(1_700_000_001_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(SessionId::new()),
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::StagedPushes { pushes: vec![] });
}

/// Staging entries that lack a matching audit row (e.g. an orphan
/// directory left over from a crash between `staging_store.stage`
/// and `record_git_push_request`) must be excluded by the session
/// filter even when the operator filters by a "real" session id.
/// The audit log is the source of truth for the
/// staged-push ↔ session mapping; an orphan staging directory has no
/// session.
#[tokio::test]
async fn list_staged_pushes_with_session_filter_excludes_orphan_staging() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;

    // One legitimate staged push under `session_id`.
    let real = stage_with_audit(
        &state,
        session_id,
        b"real".to_vec(),
        UnixMillis::from_millis(1_700_000_001_000),
        UnixMillis::from_millis(1_700_000_001_500),
    )
    .await;

    // One staging-only entry with no audit row.
    let orphan_request_id = RequestId::new();
    let metadata = crate::vm_git::VmGitPushMetadata::new(
        sample_clone_repo(),
        sample_branch(),
        None,
        sample_object_id('c'),
    );
    let staging = state.staging_store.as_ref().unwrap().clone();
    tokio::task::spawn_blocking(move || {
        staging
            .stage(
                orphan_request_id,
                UnixMillis::from_millis(1_700_000_002_000),
                metadata,
                b"orphan".to_vec(),
            )
            .unwrap();
    })
    .await
    .unwrap();

    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(session_id),
        },
        &state,
    )
    .await;
    let pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].push_request_id, real);
    // Sanity: the unfiltered listing still surfaces the orphan,
    // since unfiltered listing reflects on-disk staging only and
    // not the audit DB. Today the `show` endpoint will surface the
    // orphan as an error; that contract is unchanged.
    let resp = dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
    let pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    assert_eq!(pushes.len(), 2);
}

/// Codex R4 P2: a session-filtered listing must not be broken by an
/// unrelated malformed staging dir. The audit log names the request
/// ids that belong to the session, and we load only those — so a
/// corrupt sibling dir (e.g. left by external tampering or an
/// interrupted write) is invisible to the filtered call.
#[tokio::test]
async fn list_staged_pushes_with_session_filter_ignores_unrelated_malformed_dir() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;

    let real = stage_with_audit(
        &state,
        session_id,
        b"real".to_vec(),
        UnixMillis::from_millis(1_700_000_010_000),
        UnixMillis::from_millis(1_700_000_010_500),
    )
    .await;

    // Drop a malformed directory into the staging root that has no
    // audit row and a name we never look up. Pre-fix this would
    // make `staging_store.list()` fail and surface as an error from
    // the filtered call.
    let staging_root = state.staging_store.as_ref().unwrap().root().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let bogus = staging_root.join("staged").join("not-a-uuid");
        std::fs::create_dir_all(&bogus).unwrap();
    })
    .await
    .unwrap();

    let resp = dispatch_message(
        ClientMessage::ListStagedPushes {
            session_id: Some(session_id),
        },
        &state,
    )
    .await;
    let pushes = match resp {
        ServerMessage::StagedPushes { pushes } => pushes,
        other => panic!("expected StagedPushes, got {other:?}"),
    };
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].push_request_id, real);
}

#[tokio::test]
async fn show_staged_push_without_staging_configured_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::ShowStagedPush {
            request_id: RequestId::new(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("staging"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn show_staged_push_for_unknown_request_id_returns_unknown_staged_push() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let request_id = RequestId::new();
    let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
    assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
}

#[tokio::test]
async fn show_staged_push_returns_detail_joining_staging_and_audit() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;

    let staged_at = UnixMillis::from_millis(1_700_000_500_000);
    let received_at = UnixMillis::from_millis(1_700_000_500_250);
    let bundle = b"PACK bundle payload".to_vec();
    let request_id =
        stage_with_audit(&state, session_id, bundle.clone(), staged_at, received_at).await;

    let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
    let push = match resp {
        ServerMessage::StagedPush { push } => push,
        other => panic!("expected StagedPush, got {other:?}"),
    };
    assert_eq!(push.summary.push_request_id, request_id);
    assert_eq!(push.summary.staged_at, staged_at);
    assert_eq!(push.bundle_bytes, bundle.len() as u64);
    assert_eq!(push.audit.session_id, session_id);
    assert_eq!(push.audit.received_at, received_at);
    // No outcome row recorded → audit.result stays None.
    assert_eq!(push.audit.result, None);
}

/// If the on-disk staging entry has no matching audit row, the
/// broker must surface that as an Error rather than fabricating a
/// `received_at`. This protects the audit-chain invariant that
/// every staged push has a request row.
#[tokio::test]
async fn show_staged_push_with_orphan_staging_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);

    let request_id = RequestId::new();
    let metadata = crate::vm_git::VmGitPushMetadata::new(
        sample_clone_repo(),
        sample_branch(),
        None,
        sample_object_id('c'),
    );
    let staging = state.staging_store.as_ref().unwrap().clone();
    tokio::task::spawn_blocking(move || {
        staging
            .stage(
                request_id,
                UnixMillis::from_millis(1),
                metadata,
                b"orphan".to_vec(),
            )
            .unwrap();
    })
    .await
    .unwrap();

    let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("no audit record"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
