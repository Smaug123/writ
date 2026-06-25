//! Capability/token minting, agent-registry, and policy-decision tests.

use super::test_support::*;
use super::*;
use crate::core::AgentKind;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn error_with_source_chain_appends_nested_sources() {
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct Inner;
    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "dns error: failed to lookup address")
        }
    }
    impl Error for Inner {}

    #[derive(Debug)]
    struct Outer(Inner);
    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // mimics reqwest's opaque outer Display
            write!(
                f,
                "error sending request for url (https://api.github.com/...)"
            )
        }
    }
    impl Error for Outer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    // The opaque outer message keeps its hidden cause via the source chain.
    assert_eq!(
        error_with_source_chain(&Outer(Inner)),
        "error sending request for url (https://api.github.com/...): \
         dns error: failed to lookup address"
    );
    // A sourceless error is just its Display.
    assert_eq!(
        error_with_source_chain(&Inner),
        "dns error: failed to lookup address"
    );
}

#[test]
fn capability_outcome_debug_redacts_granted_token() {
    let outcome = CapabilityOutcome::Granted {
        token: "ghs_should_not_print".into(),
        expires_at: UnixMillis::from_millis(1_700_000_000_000),
    };

    let debug = format!("{outcome:?}");

    assert!(!debug.contains("ghs_should_not_print"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(debug.contains("expires_at"), "{debug}");
}

#[tokio::test]
async fn request_not_on_allowlist_is_denied() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o"); // empty allowlist

    let session_id = open_session(&state).await;

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Write,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    assert!(
        matches!(resp, ServerMessage::Denied { .. }),
        "expected Denied, got {resp:?}"
    );
}

#[tokio::test]
async fn request_on_closed_session_returns_closed_session_variant_without_minting() {
    // If a client closes the session and then tries to mint, the
    // broker must reject rather than issue a credential and audit
    // it against a session that is already "quiet" on paper. This
    // covers the happy-path (non-racy) case where the close lands
    // before dispatch_capability starts; the audit-layer check is
    // what catches the rare race where close lands during the
    // minter's await, exercised in audit.rs.
    let server = MockServer::start().await;
    let state = make_state(&server, vec![repo("o", "n")], "o");
    // If dispatch_capability failed to reject a closed session and
    // the minter was still hit, the lack of a mount would cause the
    // request to fall through to a 404 and mask the bug we're
    // checking. Belt-and-braces: mount a handler that panics so a
    // minting attempt becomes loud.
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let session_id = open_session(&state).await;
    let close_resp = dispatch_message(ClientMessage::CloseSession { session_id }, &state).await;
    assert_eq!(close_resp, ServerMessage::SessionClosed);

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    assert_eq!(resp, ServerMessage::ClosedSession { session_id });

    // No audit row should have been recorded for the post-close
    // request attempt.
    assert!(
        state
            .audit
            .list_grants_for_session(session_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn request_for_unknown_session_returns_unknown_session_variant() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![repo("o", "n")], "o");
    let unknown: SessionId = "00000000-0000-0000-0000-deadbeef0002".parse().unwrap();

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id: unknown,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    assert_eq!(
        resp,
        ServerMessage::UnknownSession {
            session_id: unknown,
        },
    );
}

#[tokio::test]
async fn request_on_allowlisted_repo_returns_token() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![repo("o", "n")], "o");
    let session_id = open_session(&state).await;

    let expiry = expiry_str_from_now(3600);
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_test_token",
            "expires_at": expiry,
            "permissions": {"contents": "read", "metadata": "read"},
            "repository_selection": "selected",
            "repositories": [{"full_name": "o/n"}]
        })))
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::TokenGranted { token, expires_at } => {
            assert_eq!(token, "ghs_test_token");
            assert!(expires_at.as_millis() > 0);
        }
        other => panic!("expected TokenGranted, got {other:?}"),
    }
}

#[tokio::test]
async fn request_uses_github_app_for_session_agent_kind() {
    let server = MockServer::start().await;
    let state = make_agent_registry_state(&server);
    let session_id = match dispatch_message(
        ClientMessage::OpenSession {
            label: None,
            agent_kind: Some(AgentKind::Codex),
            agent_model: Some("claude-opus-misleading".into()),
        },
        &state,
    )
    .await
    {
        ServerMessage::SessionOpened { session_id } => session_id,
        other => panic!("open_session failed: {other:?}"),
    };

    Mock::given(method("POST"))
        .and(path("/app/installations/111/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/app/installations/222/access_tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_codex_token",
            "expires_at": expiry_str_from_now(3600),
            "permissions": {"contents": "read", "metadata": "read"},
            "repository_selection": "selected",
            "repositories": [{"full_name": "o/n"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::TokenGranted { token, .. } => {
            assert_eq!(token, "ghs_codex_token");
        }
        other => panic!("expected TokenGranted, got {other:?}"),
    }

    let grants = state.audit.list_grants_for_session(session_id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].github_app_id, Some(202));
}

#[tokio::test]
async fn agent_registry_rejects_session_open_without_agent_kind() {
    let server = MockServer::start().await;
    let state = make_agent_registry_state(&server);

    Mock::given(method("POST"))
        .and(path("/app/installations/111/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/app/installations/222/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: Some("claude-opus-misleading".into()),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("--agent claude"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_registry_rejects_agent_vm_start_without_agent_kind() {
    let server = MockServer::start().await;
    let state = make_agent_registry_state(&server);

    let resp = dispatch_message(
        ClientMessage::StartAgentVm {
            label: None,
            agent_kind: None,
            agent_model: None,
            workspace: None,
            guest_command: vec!["true".into()],
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("--agent claude"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_registry_reports_missing_app_for_session_agent_kind() {
    let server = MockServer::start().await;
    let state = make_agent_registry_state_for_agents(&server, &[AgentKind::Claude]);
    let session_id = open_session_with_agent_kind(&state, Some(AgentKind::Codex)).await;

    Mock::given(method("POST"))
        .and(path("/app/installations/111/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("no GitHub App is configured for agent kind codex"),
                "got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn mint_failure_returns_bounded_label_to_agent_without_echoing_body() {
    // GitHub returns a 401 with a body the broker must not forward
    // verbatim to the agent: it could be very long, and might echo a
    // sensitive fragment (e.g. an internal identifier in an error
    // message). The protocol surface must carry only the bounded
    // label produced by `MintError::agent_message`.
    let server = MockServer::start().await;
    let state = make_state(&server, vec![repo("o", "n")], "o");
    let session_id = open_session(&state).await;

    let body_marker = "do-not-leak-this-fragment-XYZ";
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": format!("bad credentials: {body_marker}"),
        })))
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::Request {
            session_id,
            capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                access: GitHubAccess::Read,
                repo: repo("o", "n"),
            }),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                !message.contains(body_marker),
                "agent surface must not echo API body: {message}"
            );
            assert!(
                message.contains("401"),
                "agent surface should carry the status discriminant: {message}"
            );
            // Sanity-cap on the protocol message itself, mirroring
            // the in-module assertion in `agent_message_…_bounded`.
            assert!(message.len() <= 256, "message too long: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
