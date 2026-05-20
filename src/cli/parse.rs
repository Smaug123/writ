//! Pure value parsers used by `clap`'s `value_parser` attribute.
//!
//! Lifted out of the binary so each parser can be re-used (and
//! re-tested via clap's `try_parse_from`) without dragging the
//! binary's argv plumbing along.

use crate::agent_plan::{CorrelationId, PlanId, Stage};
use crate::core::AgentKind;

pub fn parse_agent_kind(raw: &str) -> Result<AgentKind, String> {
    raw.parse::<AgentKind>().map_err(|err| err.to_string())
}

pub fn parse_correlation_id(raw: &str) -> Result<CorrelationId, String> {
    CorrelationId::try_new(raw).map_err(|err| err.to_string())
}

pub fn parse_stage(raw: &str) -> Result<Stage, String> {
    raw.parse::<Stage>().map_err(|err| err.to_string())
}

pub fn parse_plan_id(raw: &str) -> Result<PlanId, String> {
    raw.parse::<PlanId>().map_err(|err| err.to_string())
}
