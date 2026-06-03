//! Wire-level reference name for a Git notes ref that bailiff hands to
//! writ on a `RunAgent` request. The ref tells writ where in bailiff's
//! repo to attach the signed output note. See
//! `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! Validation is intentionally narrow for v1: enough to reject obvious
//! misuse on the wire (empty refs, NUL bytes, `..` traversal, refs that
//! don't live under `refs/`), but not the full Git refname grammar. The
//! authoritative gate is git itself — if a malformed name slips past the
//! v1 check, the eventual blob/note write fails at the git boundary
//! and surfaces as a `RunAgent` error. Tighten this when a real abuse
//! case turns up.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const REFS_PREFIX: &str = "refs/";

/// A validated git ref name suitable for naming a notes ref.
///
/// Constructed only via [`NotesRef::try_new`] (or its `FromStr`/
/// `Deserialize` equivalents). The wrapped string is the verbatim ref
/// name, e.g. `refs/notes/writ/agent-outputs`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NotesRef(String);

impl NotesRef {
    /// Validate a candidate string and wrap it. The rules are listed at
    /// the module level; the goal is "obvious misuse rejected at the
    /// wire", not full git-refname coverage.
    pub fn try_new(s: impl Into<String>) -> Result<Self, NotesRefError> {
        let s = s.into();
        if s.is_empty() {
            return Err(NotesRefError::Empty);
        }
        if s.contains('\0') {
            return Err(NotesRefError::NulByte);
        }
        if s.chars().any(char::is_whitespace) {
            return Err(NotesRefError::Whitespace);
        }
        if !s.starts_with(REFS_PREFIX) {
            return Err(NotesRefError::MissingRefsPrefix);
        }
        // Reject `..` traversal and empty components in one pass.
        for component in s.split('/') {
            if component.is_empty() {
                return Err(NotesRefError::EmptyComponent);
            }
            if component == ".." || component == "." {
                return Err(NotesRefError::TraversalComponent);
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NotesRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for NotesRef {
    type Err = NotesRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl Serialize for NotesRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NotesRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NotesRefError {
    #[error("notes ref must not be empty")]
    Empty,
    #[error("notes ref must not contain NUL bytes")]
    NulByte,
    #[error("notes ref must not contain whitespace")]
    Whitespace,
    #[error("notes ref must start with `refs/`")]
    MissingRefsPrefix,
    #[error("notes ref must not have empty path components")]
    EmptyComponent,
    #[error("notes ref must not have `.` or `..` path components")]
    TraversalComponent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn accepts_a_normal_notes_ref() {
        let r = NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap();
        assert_eq!(r.as_str(), "refs/notes/writ/agent-outputs");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(NotesRef::try_new(""), Err(NotesRefError::Empty));
    }

    #[test]
    fn rejects_nul_byte() {
        assert_eq!(
            NotesRef::try_new("refs/notes/\0bad"),
            Err(NotesRefError::NulByte)
        );
    }

    #[test]
    fn rejects_whitespace() {
        assert_eq!(
            NotesRef::try_new("refs/notes/with space"),
            Err(NotesRefError::Whitespace)
        );
        assert_eq!(
            NotesRef::try_new(" refs/notes/x"),
            Err(NotesRefError::Whitespace)
        );
        assert_eq!(
            NotesRef::try_new("refs/notes/x\n"),
            Err(NotesRefError::Whitespace)
        );
    }

    #[test]
    fn rejects_missing_refs_prefix() {
        assert_eq!(
            NotesRef::try_new("notes/writ"),
            Err(NotesRefError::MissingRefsPrefix)
        );
        assert_eq!(
            NotesRef::try_new("/refs/notes/writ"),
            Err(NotesRefError::MissingRefsPrefix)
        );
    }

    #[test]
    fn rejects_empty_components() {
        assert_eq!(
            NotesRef::try_new("refs//notes/writ"),
            Err(NotesRefError::EmptyComponent)
        );
        assert_eq!(
            NotesRef::try_new("refs/notes/writ/"),
            Err(NotesRefError::EmptyComponent)
        );
    }

    #[test]
    fn rejects_traversal_components() {
        assert_eq!(
            NotesRef::try_new("refs/notes/../writ"),
            Err(NotesRefError::TraversalComponent)
        );
        assert_eq!(
            NotesRef::try_new("refs/./writ"),
            Err(NotesRefError::TraversalComponent)
        );
    }

    #[test]
    fn from_str_uses_try_new() {
        assert_eq!(
            NotesRef::from_str("refs/notes/writ").unwrap().as_str(),
            "refs/notes/writ"
        );
        assert!(NotesRef::from_str("").is_err());
    }

    #[test]
    fn serialises_as_bare_string() {
        let r = NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#""refs/notes/writ/agent-outputs""#);
    }

    #[test]
    fn deserialises_through_try_new() {
        let back: NotesRef = serde_json::from_str(r#""refs/notes/writ/agent-outputs""#).unwrap();
        assert_eq!(back.as_str(), "refs/notes/writ/agent-outputs");
    }

    /// A wire payload whose ref is invalid must be rejected at parse
    /// time, not silently wrapped. The error message must contain the
    /// concrete rule so the operator can fix the input.
    #[test]
    fn deserialise_rejects_invalid_with_descriptive_error() {
        let err = serde_json::from_str::<NotesRef>(r#""no-refs-prefix""#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("refs/"),
            "expected descriptive error mentioning `refs/`, got: {msg}"
        );
    }
}
