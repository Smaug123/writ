//! Wire-level vocabulary for what writ permits an agent to do during
//! a `run-agent` invocation. Bailiff picks the set when launching an
//! agent; writ enforces each variant through the existing `policy::*`
//! oracle. See `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! Closed enum: a new variant requires both daemons to know it. v1
//! variants intentionally start narrow — there is no plumbing yet to
//! exercise them — so the wire surface is small enough to reshape
//! before any consumer locks in.

use super::RepoRef;
use serde::{Deserialize, Serialize};

/// Authority granted to a single agent run.
///
/// Internally tagged on `kind` rather than externally tagged so the
/// JSON shape stays flat — every variant is a single object with
/// `kind` plus its own fields. `deny_unknown_fields` catches typos
/// on the wire instead of silently dropping them and proceeding with
/// a defaulted value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilitySet {
    /// Read-only access to a workspace repo. Used for plan-stage and
    /// review-stage agents under today's workflow vocabulary.
    WorkspaceRead { repo: RepoRef },
    /// Read + branch-write access to a workspace repo. Writes still
    /// flow through writ's git-push staging on commit; the branch
    /// name and base SHA are part of the *request* the agent makes,
    /// not part of the capability set. Used for execute-stage agents.
    WorkspaceWrite { repo: RepoRef },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        }
    }

    #[test]
    fn workspace_read_roundtrips_through_json() {
        let cap = CapabilitySet::WorkspaceRead {
            repo: sample_repo(),
        };
        let j = serde_json::to_string(&cap).unwrap();
        let back: CapabilitySet = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cap);
    }

    #[test]
    fn workspace_write_roundtrips_through_json() {
        let cap = CapabilitySet::WorkspaceWrite {
            repo: sample_repo(),
        };
        let j = serde_json::to_string(&cap).unwrap();
        let back: CapabilitySet = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cap);
    }

    /// Pin the wire-level kind names. Regressing these silently (e.g.
    /// via a future `rename_all` change) would break every deployed
    /// client at once, so they want a literal pin.
    #[test]
    fn variant_tags_are_snake_cased_literals() {
        let read = CapabilitySet::WorkspaceRead {
            repo: sample_repo(),
        };
        let write = CapabilitySet::WorkspaceWrite {
            repo: sample_repo(),
        };
        let read_value: serde_json::Value = serde_json::to_value(&read).unwrap();
        let write_value: serde_json::Value = serde_json::to_value(&write).unwrap();
        assert_eq!(
            read_value["kind"],
            serde_json::Value::String("workspace_read".into())
        );
        assert_eq!(
            write_value["kind"],
            serde_json::Value::String("workspace_write".into())
        );
    }

    /// A `kind` tag for a variant that doesn't exist must be a hard
    /// deserialisation error, not a silent fall-through to a default
    /// variant.
    #[test]
    fn unknown_kind_is_rejected() {
        let j = r#"{"kind":"workspace_nope","repo":"smaug123/writ"}"#;
        let err = serde_json::from_str::<CapabilitySet>(j).unwrap_err();
        assert!(
            err.to_string().contains("workspace_nope")
                || err.to_string().contains("unknown variant"),
            "expected unknown-variant error, got: {err}"
        );
    }

    /// Extra fields on a known variant are rejected by
    /// `deny_unknown_fields`. Catches typos like `repor` and the
    /// future risk that an additional field is added to one variant
    /// but not the variants its operators are paginating between.
    #[test]
    fn unknown_field_on_known_variant_is_rejected() {
        let j = r#"{"kind":"workspace_read","repo":"smaug123/writ","extra":1}"#;
        let err = serde_json::from_str::<CapabilitySet>(j).unwrap_err();
        assert!(
            err.to_string().contains("extra") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }
}
