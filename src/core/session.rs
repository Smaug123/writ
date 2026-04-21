use super::{SessionId, UnixSeconds};
use serde::{Deserialize, Serialize};

/// A persistent record of one agent session. The session ID is broker-issued;
/// client-provided fields (`label`, `agent_model`) are informational only and
/// carry no semantic weight in policy decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub label: Option<String>,
    pub agent_model: Option<String>,
    pub opened_at: UnixSeconds,
    pub closed_at: Option<UnixSeconds>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrips_when_open() {
        let s = SessionRecord {
            session_id: SessionId::new(),
            label: Some("fixing bug 123".into()),
            agent_model: Some("claude-opus-4-7".into()),
            opened_at: UnixSeconds::from_i64(1_700_000_000),
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
            agent_model: None,
            opened_at: UnixSeconds::from_i64(1_700_000_000),
            closed_at: Some(UnixSeconds::from_i64(1_700_001_000)),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: SessionRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }
}
