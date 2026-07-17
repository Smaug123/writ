//! Bailiff-owned decision-note primitives.
//!
//! Types in this module model the operator-driven accept/reject
//! verdict bailiff records against a previously-submitted plan.
//!
//! See `docs/plans/2026-05-16-slice-d1-decide.md` for the slice plan.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Largest byte length accepted for a [`Decider`] string. Operator
/// attribution strings take the form `cli:<user>` or `agent:<run_id>`.
pub const MAX_DECIDER_BYTES: usize = 256;

/// Operator verdict on a submitted plan. We use bare `Rejected` (no
/// `Restart` suffix) because bailiff does no auto-anything: "rejected"
/// is "this plan is dead; the operator does whatever they want next."
///
/// Serialised as `"accepted"` / `"rejected"` — short, snake_case,
/// matching the surrounding convention.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Accepted,
    Rejected,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("unknown decision {0:?}; expected accepted or rejected")]
pub struct DecisionParseError(String);

impl FromStr for Decision {
    type Err = DecisionParseError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            _ => Err(DecisionParseError(raw.to_string())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeciderError {
    #[error("decider must not be empty")]
    Empty,
    #[error("decider is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLong { byte_len: usize, max_bytes: usize },
    #[error("decider contains an embedded NUL byte")]
    EmbeddedNul,
}

/// Free-form attribution for a [`Decision`]: who (or what) made the
/// call. Today the bailiff CLI writes `cli:<user>`; a future
/// orchestrator agent may write `agent:<run_id>`. The string is
/// opaque to bailiff and stored verbatim, but parsed at the wire
/// boundary so invariant violations surface as typed errors rather
/// than as JSON-deserialise failures with poor messages.
///
/// Invariants:
/// - non-empty
/// - byte length ≤ [`MAX_DECIDER_BYTES`]
/// - no embedded NUL (decision notes round-trip through JSON whose
///   string type accepts `\0`, but downstream tooling — `git
///   notes show`, terminal pagers, audit-log replay — treats NULs as
///   string terminators; rejecting them up front keeps the wire
///   form free of footguns).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Decider(String);

impl Decider {
    pub fn try_new(decider: impl Into<String>) -> Result<Self, DeciderError> {
        let decider = decider.into();
        if decider.is_empty() {
            return Err(DeciderError::Empty);
        }
        if decider.len() > MAX_DECIDER_BYTES {
            return Err(DeciderError::TooLong {
                byte_len: decider.len(),
                max_bytes: MAX_DECIDER_BYTES,
            });
        }
        if decider.as_bytes().contains(&0) {
            return Err(DeciderError::EmbeddedNul);
        }
        Ok(Self(decider))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Decider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Decider {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Decider {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Decision enum -------------------------------------------------------

    /// Every variant's `as_str`, `Display`, serde serialisation, and
    /// `FromStr` agree on the canonical form. Locks the wire shape:
    /// a future rename to (say) `Decision::Accept` would have to
    /// change four projections at once, none of which can drift.
    #[test]
    fn decision_text_projections_agree_for_every_variant() {
        for d in [Decision::Accepted, Decision::Rejected] {
            let s = d.as_str();
            assert_eq!(d.to_string(), s, "Display disagrees with as_str");
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(
                json,
                format!("\"{s}\""),
                "serde serialises differently from as_str"
            );
            let parsed: Decision = s.parse().unwrap();
            assert_eq!(parsed, d, "FromStr does not invert as_str");
        }
    }

    /// Pin the on-wire strings explicitly — `decision_text_projections`
    /// above checks self-consistency but a typo'd `as_str` would still
    /// be self-consistent. This test breaks if anyone renames the
    /// serialised form.
    #[test]
    fn decision_wire_form_is_pinned() {
        assert_eq!(Decision::Accepted.as_str(), "accepted");
        assert_eq!(Decision::Rejected.as_str(), "rejected");
    }

    /// `FromStr` rejects strings that aren't a known variant. The
    /// `rejected_restart` spelling from writ's former decision enum is
    /// explicitly **not** accepted: bailiff's `Decision` is a distinct
    /// shape, not an alias.
    #[test]
    fn decision_from_str_rejects_unknown_and_legacy_spellings() {
        for bad in [
            "",
            "ACCEPTED",
            "rejected_restart",
            "Rejected",
            "accept",
            "reject",
        ] {
            assert!(
                bad.parse::<Decision>().is_err(),
                "FromStr should have rejected {bad:?}"
            );
        }
    }

    /// `Decision` round-trips through JSON. Standard pin; matches the
    /// pattern in `bailiff_plan_note::tests`.
    #[test]
    fn decision_round_trips_through_json() {
        for d in [Decision::Accepted, Decision::Rejected] {
            let bytes = serde_json::to_vec(&d).unwrap();
            let back: Decision = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(back, d);
        }
    }

    /// JSON deserialise rejects unknown variants. `deny_unknown_fields`
    /// only catches extra struct fields; a bogus enum tag has to bounce
    /// here.
    #[test]
    fn decision_json_rejects_unknown_variant() {
        assert!(serde_json::from_str::<Decision>("\"rejected_restart\"").is_err());
        assert!(serde_json::from_str::<Decision>("\"accept\"").is_err());
    }

    // --- Decider newtype -----------------------------------------------------

    #[test]
    fn decider_accepts_typical_attribution_strings() {
        for ok in [
            "cli:alice",
            "cli:unknown",
            "agent:6f7c3e1f-1c5e-4b1d-9b6c-1f1c2b3d4e5f",
            "a",
            &"x".repeat(MAX_DECIDER_BYTES),
        ] {
            let parsed = Decider::try_new(ok)
                .unwrap_or_else(|e| panic!("expected {ok:?} to parse, got {e}"));
            assert_eq!(parsed.as_str(), ok);
        }
    }

    #[test]
    fn decider_rejects_empty_too_long_and_embedded_nul() {
        assert!(matches!(Decider::try_new(""), Err(DeciderError::Empty)));
        let oversize = "x".repeat(MAX_DECIDER_BYTES + 1);
        assert!(matches!(
            Decider::try_new(&oversize),
            Err(DeciderError::TooLong { .. })
        ));
        assert!(matches!(
            Decider::try_new("cli:al\0ce"),
            Err(DeciderError::EmbeddedNul)
        ));
    }

    #[test]
    fn decider_serializes_as_plain_string() {
        let d = Decider::try_new("cli:alice").unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"cli:alice\"");
        let back: Decider = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    /// Deserialising the wire form runs through `try_new`, so a JSON
    /// string that violates the invariants is rejected at the wire
    /// boundary rather than reaching the note body.
    #[test]
    fn decider_deserialization_runs_validation() {
        assert!(serde_json::from_str::<Decider>("\"\"").is_err());
        let oversize = format!("\"{}\"", "x".repeat(MAX_DECIDER_BYTES + 1));
        assert!(serde_json::from_str::<Decider>(&oversize).is_err());
        assert!(serde_json::from_str::<Decider>("\"cli:al\\u0000ce\"").is_err());
    }

    /// `Display` matches `as_str`. A divergence here would mean a
    /// `{decider}` interpolation in tracing output disagrees with the
    /// serialised wire form, which is exactly the kind of bug an
    /// audit trail makes impossible to chase down.
    #[test]
    fn decider_display_matches_as_str() {
        let d = Decider::try_new("cli:alice").unwrap();
        assert_eq!(format!("{d}"), d.as_str());
    }
}
