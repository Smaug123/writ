use std::str::FromStr;

use super::{SessionId, UnixMillis};
use serde::{Deserialize, Serialize};

/// Coarse identity selected for the agent runtime behind a session.
///
/// This is deliberately separate from `agent_model`: the model string is
/// free-form audit metadata, while `AgentKind` is the closed value the broker
/// treats as the session identity for authority-bearing configuration such as
/// GitHub App selection. The broker does not authenticate that the caller is
/// actually Claude or Codex; the socket/VM boundary is responsible for that.
///
/// If you add a variant, add a matching audit migration: schema v4 has a
/// SQLite CHECK constraint enumerating the accepted wire strings.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Claude,
    Codex,
}

/// A persistent record of one agent session. The session ID is broker-issued;
/// `agent_kind` is the session-level classification used for authority
/// selection and is normally supplied by the client at session open. The
/// free-form client fields (`label`, `agent_model`) are informational only and
/// carry no semantic weight in policy decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_kind: Option<AgentKind>,
    pub agent_model: Option<String>,
    pub opened_at: UnixMillis,
    pub closed_at: Option<UnixMillis>,
}

impl AgentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

impl std::fmt::Display for AgentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("unknown agent kind {0:?}; expected claude or codex")]
pub struct AgentKindParseError(String);

impl FromStr for AgentKind {
    type Err = AgentKindParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            _ => Err(AgentKindParseError(raw.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrips_when_open() {
        let s = SessionRecord {
            session_id: SessionId::new(),
            label: Some("fixing bug 123".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: SessionRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn session_roundtrips_when_closed() {
        let s = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: Some(UnixMillis::from_millis(1_700_001_000)),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: SessionRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn agent_kind_roundtrips_as_stable_string() {
        assert_eq!(
            serde_json::to_string(&AgentKind::Claude).unwrap(),
            r#""claude""#
        );
        assert_eq!("codex".parse::<AgentKind>().unwrap(), AgentKind::Codex);
        assert!("gpt".parse::<AgentKind>().is_err());
    }
}
