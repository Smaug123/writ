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

use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
use crate::core::{AgentKind, CapabilityRequest, SessionId, UnixMillis};
use crate::vm_git::AgentVmWorkspaceBootstrap;

/// A persisted daemon-managed agent VM session as reported by
/// [`ServerMessage::AgentVmSessions`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentVmSessionInfo {
    pub session_id: SessionId,
    pub status: AgentVmSessionStateStatus,
    pub subnet_index: u16,
    pub vm_name: String,
    pub network_name: String,
    pub broker_urls: Vec<String>,
    pub runtime_attached: bool,
}

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
        /// Trusted coarse agent identity used by the broker to choose
        /// authority-bearing backend configuration.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_kind: Option<AgentKind>,
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
    /// Start an isolated Apple-container agent VM managed by the daemon.
    /// The daemon assigns the session ID and broker endpoint.
    StartAgentVm {
        /// Human-readable description stored in the audit log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        label: Option<String>,
        /// Trusted coarse agent identity used by the broker to choose
        /// authority-bearing backend configuration.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_kind: Option<AgentKind>,
        /// Model identifier stored in the audit log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_model: Option<String>,
        /// Optional clean repo checkout and source/substitute warmup to
        /// complete before the guest agent command starts.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        workspace: Option<AgentVmWorkspaceBootstrap>,
        /// Command to run inside the VM after lifecycle preflight succeeds.
        guest_command: Vec<String>,
    },
    /// Stop a daemon-managed agent VM session and close its audit session.
    StopAgentVm { session_id: SessionId },
    /// List persisted daemon-managed agent VM sessions. Records without an
    /// attached in-memory runtime are cleanup obligations after daemon restart.
    ListAgentVms,
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
    TokenGranted {
        token: String,
        expires_at: UnixMillis,
    },
    /// Policy denied the request; `reason` is a human-readable explanation.
    Denied { reason: String },
    /// A daemon-managed agent VM is running and can reach this broker URL from
    /// inside the guest. The VM HTTP bearer token is injected into the guest
    /// environment, not returned over the host protocol.
    AgentVmStarted {
        session_id: SessionId,
        broker_url: String,
    },
    /// Acknowledges [`ClientMessage::StopAgentVm`].
    AgentVmStopped,
    /// Reports persisted daemon-managed agent VM sessions.
    AgentVmSessions { sessions: Vec<AgentVmSessionInfo> },
    /// Something went wrong (mint error, unknown session, audit write
    /// failure, …). The agent should surface `message` to the user and
    /// not retry automatically.
    Error { message: String },
}

impl std::fmt::Debug for ServerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionOpened { session_id } => f
                .debug_struct("SessionOpened")
                .field("session_id", session_id)
                .finish(),
            Self::SessionClosed => write!(f, "SessionClosed"),
            // Token is a live credential; redact it in debug output so a
            // stray `dbg!` or tracing span doesn't spray it into logs.
            Self::TokenGranted { expires_at, .. } => f
                .debug_struct("TokenGranted")
                .field("token", &"<redacted>")
                .field("expires_at", expires_at)
                .finish(),
            Self::Denied { reason } => f.debug_struct("Denied").field("reason", reason).finish(),
            Self::AgentVmStarted {
                session_id,
                broker_url,
            } => f
                .debug_struct("AgentVmStarted")
                .field("session_id", session_id)
                .field("broker_url", broker_url)
                .finish(),
            Self::AgentVmStopped => write!(f, "AgentVmStopped"),
            Self::AgentVmSessions { sessions } => f
                .debug_struct("AgentVmSessions")
                .field("sessions", sessions)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, GitHubRequest, RepoRef};
    use crate::vm_git::{GitCloneRepo, WorkspaceWarmMode};
    use proptest::prelude::*;
    use std::path::PathBuf;

    fn fixed_session_id() -> SessionId {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "o".into(),
            name: "n".into(),
        }
    }

    fn sample_clone_repo() -> GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    // --- ClientMessage roundtrips -----------------------------------------

    #[test]
    fn open_session_with_fields_roundtrips() {
        let msg = ClientMessage::OpenSession {
            label: Some("fix bug 42".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn open_session_without_fields_roundtrips() {
        let msg = ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn close_session_roundtrips() {
        let msg = ClientMessage::CloseSession {
            session_id: fixed_session_id(),
        };
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

    #[test]
    fn start_agent_vm_roundtrips() {
        let msg = ClientMessage::StartAgentVm {
            label: Some("agent vm".into()),
            agent_kind: Some(AgentKind::Codex),
            agent_model: Some("gpt-test".into()),
            workspace: None,
            guest_command: vec!["sleep".into(), "600".into()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn start_agent_vm_with_workspace_roundtrips() {
        let msg = ClientMessage::StartAgentVm {
            label: Some("agent vm".into()),
            agent_kind: Some(AgentKind::Codex),
            agent_model: Some("gpt-test".into()),
            workspace: Some(AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm: WorkspaceWarmMode::DevShell,
            }),
            guest_command: vec!["codex".into()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn stop_agent_vm_roundtrips() {
        let msg = ClientMessage::StopAgentVm {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_agent_vms_roundtrips() {
        let msg = ClientMessage::ListAgentVms;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    // --- ServerMessage roundtrips -----------------------------------------

    #[test]
    fn session_opened_roundtrips() {
        let msg = ServerMessage::SessionOpened {
            session_id: fixed_session_id(),
        };
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
        let msg = ServerMessage::Denied {
            reason: "not on allowlist".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn agent_vm_started_roundtrips() {
        let msg = ServerMessage::AgentVmStarted {
            session_id: fixed_session_id(),
            broker_url: "http://192.168.252.1:51375/".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn agent_vm_stopped_roundtrips() {
        let json = serde_json::to_string(&ServerMessage::AgentVmStopped).unwrap();
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&json).unwrap(),
            ServerMessage::AgentVmStopped,
        );
    }

    #[test]
    fn agent_vm_sessions_roundtrips() {
        let msg = ServerMessage::AgentVmSessions {
            sessions: vec![AgentVmSessionInfo {
                session_id: fixed_session_id(),
                status: AgentVmSessionStateStatus::Running,
                subnet_index: 252,
                vm_name: format!("writ-agent-vm-{}", fixed_session_id()),
                network_name: format!("writ-agent-net-{}", fixed_session_id()),
                broker_urls: vec!["http://192.168.252.1:51375/".into()],
                runtime_attached: false,
            }],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn error_roundtrips() {
        let msg = ServerMessage::Error {
            message: "mint failed".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    // --- Wire format pins -------------------------------------------------

    #[test]
    fn open_session_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        })
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
            capability: CapabilityRequest::GitHub(GitHubRequest::Metadata {
                repo: sample_repo(),
            }),
        })
        .unwrap();
        assert_eq!(v["type"], "request");
    }

    #[test]
    fn agent_vm_type_tags() {
        let start: serde_json::Value = serde_json::to_value(ClientMessage::StartAgentVm {
            label: None,
            agent_kind: None,
            agent_model: None,
            workspace: None,
            guest_command: vec!["true".into()],
        })
        .unwrap();
        assert_eq!(start["type"], "start_agent_vm");

        let stop: serde_json::Value = serde_json::to_value(ClientMessage::StopAgentVm {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(stop["type"], "stop_agent_vm");

        let started: serde_json::Value = serde_json::to_value(ServerMessage::AgentVmStarted {
            session_id: fixed_session_id(),
            broker_url: "http://192.168.252.1:51375/".into(),
        })
        .unwrap();
        assert_eq!(started["type"], "agent_vm_started");

        let stopped: serde_json::Value =
            serde_json::to_value(ServerMessage::AgentVmStopped).unwrap();
        assert_eq!(stopped["type"], "agent_vm_stopped");

        let list: serde_json::Value = serde_json::to_value(ClientMessage::ListAgentVms).unwrap();
        assert_eq!(list["type"], "list_agent_vms");

        let sessions: serde_json::Value = serde_json::to_value(ServerMessage::AgentVmSessions {
            sessions: Vec::new(),
        })
        .unwrap();
        assert_eq!(sessions["type"], "agent_vm_sessions");
    }

    #[test]
    fn open_session_omits_absent_fields() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        })
        .unwrap();
        assert!(v.get("label").is_none());
        assert!(v.get("agent_kind").is_none());
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
            let msg = ClientMessage::OpenSession { label, agent_kind: None, agent_model };
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
