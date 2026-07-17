//! Reachability state for a session's broker network path.

use serde::{Deserialize, Serialize};

/// Whether a session's broker path is currently reachable, as observed from the
/// host. Wire-facing: surfaced in `writ agent-vm list` and stored (as the
/// from/to of a transition) in the audit log. The debounced tracker that
/// *produces* it lives in the host `agent_vm_lifecycle::network_health` module;
/// this crate owns only the data type, shared by the daemon, the CLI, the wire
/// protocol, and the audit log.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHealth {
    Reachable,
    Unreachable,
    Unknown,
}

impl NetworkHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// Serde default so a record (or wire message) that predates the field
    /// deserialises as `Unknown` rather than failing.
    pub fn unknown() -> Self {
        Self::Unknown
    }
}
