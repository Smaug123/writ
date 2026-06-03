//! Session open/close lifecycle over `dispatch_message`.

use super::test_support::*;
use super::*;
use crate::core::AgentKind;
use wiremock::MockServer;

#[tokio::test]
async fn open_session_returns_session_opened_and_records_in_db() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");

    let resp = dispatch_message(
        ClientMessage::OpenSession {
            label: Some("test".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
        },
        &state,
    )
    .await;

    let session_id = match resp {
        ServerMessage::SessionOpened { session_id } => session_id,
        other => panic!("expected SessionOpened, got {other:?}"),
    };

    // DB must contain the record
    let record = state.audit.get_session(session_id).unwrap().unwrap();
    assert_eq!(record.label.as_deref(), Some("test"));
    assert!(record.closed_at.is_none());
}

#[tokio::test]
async fn close_session_after_open_returns_session_closed_and_sets_timestamp() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");

    let session_id = match dispatch_message(
        ClientMessage::OpenSession {
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
        },
        &state,
    )
    .await
    {
        ServerMessage::SessionOpened { session_id } => session_id,
        other => panic!("{other:?}"),
    };

    let resp = dispatch_message(ClientMessage::CloseSession { session_id }, &state).await;
    assert_eq!(resp, ServerMessage::SessionClosed);

    let record = state.audit.get_session(session_id).unwrap().unwrap();
    assert!(record.closed_at.is_some());
}

#[tokio::test]
async fn close_unknown_session_is_silently_accepted() {
    // The UPDATE simply matches 0 rows; no error is returned.
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let unknown: SessionId = "00000000-0000-0000-0000-deadbeef0001".parse().unwrap();
    let resp = dispatch_message(
        ClientMessage::CloseSession {
            session_id: unknown,
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::SessionClosed);
}
