//! Wire protocol types for the writ Unix-socket interface.
//!
//! Every connection is a sequence of newline-terminated JSON lines.
//! The client sends one [`ClientMessage`] per line; the broker replies
//! with one [`ServerMessage`] per line. No multiplexing, no framing
//! beyond the newline.
//!
//! These types are thin wrappers over the core domain types: the
//! [`CapabilityRequest`] a client sends is exactly the struct the
//! policy engine consumes, and [`SessionId`]/[`UnixMillis`] are the
//! same values that land in the audit log. No translation layer.

use serde::{Deserialize, Serialize};

use crate::core::{CapabilityRequest, SessionId, UnixMillis};

/// A message from the agent to the broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Begin a new session. The broker assigns a session ID, records it
    /// in the audit log, and returns [`ServerMessage::SessionOpened`].
    OpenSession {
        /// Human-readable description, e.g. "fixing bug #123". Stored in
        /// the audit log; ignored by policy.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        label: Option<String>,
        /// Model identifier, e.g. "claude-opus-4-7". Informational only.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_model: Option<String>,
    },
    /// End an open session. The broker records the close timestamp.
    CloseSession { session_id: SessionId },
    /// Ask the broker to evaluate policy and, if granted, mint a
    /// credential. Returns [`ServerMessage::TokenGranted`] or
    /// [`ServerMessage::Denied`].
    Request {
        session_id: SessionId,
        capability: CapabilityRequest,
    },
}

/// A message from the broker to the agent.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Acknowledges [`ClientMessage::OpenSession`]; carries the
    /// broker-assigned session ID for use in subsequent messages.
    SessionOpened { session_id: SessionId },
    /// Acknowledges [`ClientMessage::CloseSession`].
    SessionClosed,
    /// Policy granted the request. `expires_at` is the backend-reported
    /// expiry in unix milliseconds; the grant is recorded in the audit log.
    TokenGranted { token: String, expires_at: UnixMillis },
    /// Policy denied the request; `reason` is a human-readable explanation.
    Denied { reason: String },
    /// Something went wrong (mint error, unknown session, audit write
    /// failure, …). The agent should surface `message` to the user and
    /// not retry automatically.
    Error { message: String },
}

impl std::fmt::Debug for ServerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionOpened { session_id } => {
                f.debug_struct("SessionOpened").field("session_id", session_id).finish()
            }
            Self::SessionClosed => write!(f, "SessionClosed"),
            // Token is a live credential; redact it in debug output so a
            // stray `dbg!` or tracing span doesn't spray it into logs.
            Self::TokenGranted { expires_at, .. } => f
                .debug_struct("TokenGranted")
                .field("token", &"<redacted>")
                .field("expires_at", expires_at)
                .finish(),
            Self::Denied { reason } => {
                f.debug_struct("Denied").field("reason", reason).finish()
            }
            Self::Error { message } => {
                f.debug_struct("Error").field("message", message).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, GitHubRequest, RepoRef};
    use proptest::prelude::*;

    fn fixed_session_id() -> SessionId {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_repo() -> RepoRef {
        RepoRef { owner: "o".into(), name: "n".into() }
    }

    // --- ClientMessage roundtrips -----------------------------------------

    #[test]
    fn open_session_with_fields_roundtrips() {
        let msg = ClientMessage::OpenSession {
            label: Some("fix bug 42".into()),
            agent_model: Some("claude-opus-4-7".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn open_session_without_fields_roundtrips() {
        let msg = ClientMessage::OpenSession { label: None, agent_model: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn close_session_roundtrips() {
        let msg = ClientMessage::CloseSession { session_id: fixed_session_id() };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn request_roundtrips() {
        let msg = ClientMessage::Request {
            session_id: fixed_session_id(),
            capability: CapabilityRequest::GitHub(GitHubRequest::Contents {
                access: GitHubAccess::Write,
                repo: sample_repo(),
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    // --- ServerMessage roundtrips -----------------------------------------

    #[test]
    fn session_opened_roundtrips() {
        let msg = ServerMessage::SessionOpened { session_id: fixed_session_id() };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn session_closed_roundtrips() {
        let json = serde_json::to_string(&ServerMessage::SessionClosed).unwrap();
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&json).unwrap(),
            ServerMessage::SessionClosed,
        );
    }

    #[test]
    fn token_granted_roundtrips() {
        let msg = ServerMessage::TokenGranted {
            token: "ghs_test".into(),
            expires_at: UnixMillis::from_millis(9_000_000_000),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn denied_roundtrips() {
        let msg = ServerMessage::Denied { reason: "not on allowlist".into() };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn error_roundtrips() {
        let msg = ServerMessage::Error { message: "mint failed".into() };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    // --- Wire format pins -------------------------------------------------

    #[test]
    fn open_session_type_tag() {
        let v: serde_json::Value =
            serde_json::to_value(ClientMessage::OpenSession { label: None, agent_model: None })
                .unwrap();
        assert_eq!(v["type"], "open_session");
    }

    #[test]
    fn close_session_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::CloseSession {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(v["type"], "close_session");
    }

    #[test]
    fn request_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::Request {
            session_id: fixed_session_id(),
            capability: CapabilityRequest::GitHub(GitHubRequest::Metadata { repo: sample_repo() }),
        })
        .unwrap();
        assert_eq!(v["type"], "request");
    }

    #[test]
    fn open_session_omits_absent_fields() {
        let v: serde_json::Value =
            serde_json::to_value(ClientMessage::OpenSession { label: None, agent_model: None })
                .unwrap();
        assert!(v.get("label").is_none());
        assert!(v.get("agent_model").is_none());
    }

    #[test]
    fn token_granted_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ServerMessage::TokenGranted {
            token: "t".into(),
            expires_at: UnixMillis::from_millis(0),
        })
        .unwrap();
        assert_eq!(v["type"], "token_granted");
    }

    #[test]
    fn denied_type_tag() {
        let v: serde_json::Value =
            serde_json::to_value(ServerMessage::Denied { reason: "x".into() }).unwrap();
        assert_eq!(v["type"], "denied");
    }

    // --- Debug redaction --------------------------------------------------

    #[test]
    fn token_granted_debug_redacts_token() {
        let msg = ServerMessage::TokenGranted {
            token: "ghs_secret_value".into(),
            expires_at: UnixMillis::from_millis(0),
        };
        let debug = format!("{msg:?}");
        assert!(!debug.contains("ghs_secret_value"));
        assert!(debug.contains("<redacted>"));
    }

    // --- Property-based ---------------------------------------------------

    proptest! {
        #[test]
        fn open_session_roundtrips_arbitrary_strings(
            label in proptest::option::of("[^\n]{0,100}"),
            agent_model in proptest::option::of("[^\n]{0,80}"),
        ) {
            let msg = ClientMessage::OpenSession { label, agent_model };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ClientMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }

        #[test]
        fn denied_roundtrips_arbitrary_reason(reason in "[^\n]{0,200}") {
            let msg = ServerMessage::Denied { reason };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ServerMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }

        #[test]
        fn error_roundtrips_arbitrary_message(message in "[^\n]{0,200}") {
            let msg = ServerMessage::Error { message };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ServerMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }
    }
}
