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

const REFS_PREFIX: &str = "refs/";

crate::validated_string! {
    /// A validated git ref name suitable for naming a notes ref.
    ///
    /// Constructed only via [`NotesRef::try_new`] (or its `FromStr`/
    /// `Deserialize` equivalents). The wrapped string is the verbatim ref
    /// name, e.g. `refs/notes/writ/agent-outputs`. The rules are listed at
    /// the module level; the goal is "obvious misuse rejected at the
    /// wire", not full git-refname coverage.
    pub struct NotesRef;
    error = NotesRefError;
    constructor = try_new;
    validate = validate_notes_ref;
}

fn validate_notes_ref(s: &str) -> Result<(), NotesRefError> {
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
    Ok(())
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
    use proptest::prelude::*;

    fn candidates() -> impl Strategy<Value = String> {
        prop_oneof![
            "refs/[a-z]{1,6}(/[a-z.]{1,6}){0,3}",
            "(refs/)?[a-z./ ]{0,20}",
            Just("refs/notes/writ/agent-outputs".to_string()),
            any::<String>(),
        ]
    }

    crate::validated_string_laws!(NotesRef, try_new, validate_notes_ref, candidates());

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
}
