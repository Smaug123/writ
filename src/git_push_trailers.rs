//! Git commit-trailer vocabulary for the push-replay pipeline.
//!
//! When the broker re-creates a staged push's commits under the App identity
//! (see `git_push_replay_walker`), it appends trailers so a published commit can
//! be traced back to the broker session and the exact bundle commit it derived
//! from. These are the validated trailer types shared by the walker, promote,
//! and approve paths.

/// One trailer to append to every replayed commit. Two shapes:
///
/// * [`TrailerSource::Fixed`] — the same `Key: value` on every commit. Use
///   for invariants like the broker session id or the operator who
///   promoted the staged push.
/// * [`TrailerSource::OriginalCommitSha`] — `Key: <bundle commit sha>` on
///   each replayed commit, so reviewers can trace any App-owned commit
///   back to the exact bundle commit it derived from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrailerSource {
    Fixed {
        key: TrailerKey,
        value: TrailerValue,
    },
    OriginalCommitSha {
        key: TrailerKey,
    },
}

/// The left side of a Git trailer (`Key: value`).
///
/// Git's own parser is permissive — anything before the first ` :` is a
/// candidate key — but the cost of accepting odd keys here is that the
/// rendered trailer block may not round-trip through other tools. The
/// validated shape matches conventional trailer keys (`Co-authored-by`,
/// `Signed-off-by`): non-empty, ASCII, starting with a letter, followed
/// by letters, digits, or `-`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrailerKey(String);

/// The right side of a Git trailer. Constrained at construction to forbid
/// the control bytes that would break the trailer block on output
/// (`\n`, `\r`, `\0`). Leading and trailing whitespace are preserved so
/// the plan is a faithful description of what the executor will emit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrailerValue(String);

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TrailerKeyError {
    #[error("trailer key must not be empty")]
    Empty,
    #[error("trailer key must start with an ASCII letter: {0:?}")]
    InvalidStart(String),
    #[error(
        "trailer key must contain only ASCII letters, digits, or '-' after the first byte: {0:?}"
    )]
    InvalidByte(String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TrailerValueError {
    #[error("trailer value must not be empty")]
    Empty,
    #[error("trailer value must not contain '\\n', '\\r', or '\\0'")]
    ContainsControlByte,
}

impl TrailerSource {
    /// The trailer key, common to both variants.
    pub fn key(&self) -> &TrailerKey {
        match self {
            TrailerSource::Fixed { key, .. } | TrailerSource::OriginalCommitSha { key } => key,
        }
    }
}

impl TrailerKey {
    pub fn new(raw: impl Into<String>) -> Result<Self, TrailerKeyError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(TrailerKeyError::Empty);
        }
        let mut bytes = raw.bytes();
        // Cannot panic: emptiness ruled out above.
        let first = bytes.next().expect("non-empty");
        if !first.is_ascii_alphabetic() {
            return Err(TrailerKeyError::InvalidStart(raw));
        }
        for byte in bytes {
            if !is_trailer_key_byte(byte) {
                return Err(TrailerKeyError::InvalidByte(raw));
            }
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TrailerValue {
    pub fn new(raw: impl Into<String>) -> Result<Self, TrailerValueError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(TrailerValueError::Empty);
        }
        if raw.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
            return Err(TrailerValueError::ContainsControlByte);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrailerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for TrailerValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

fn is_trailer_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn trailer_source_exposes_its_key() {
        let fixed = TrailerSource::Fixed {
            key: TrailerKey::new("X-Writ-Session").unwrap(),
            value: TrailerValue::new("abc-123").unwrap(),
        };
        let derived = TrailerSource::OriginalCommitSha {
            key: TrailerKey::new("X-Writ-Source-Commit").unwrap(),
        };
        assert_eq!(fixed.key().as_str(), "X-Writ-Session");
        assert_eq!(derived.key().as_str(), "X-Writ-Source-Commit");
    }

    #[test]
    fn trailer_key_accepts_conventional_shapes() {
        for raw in [
            "Co-authored-by",
            "Signed-off-by",
            "X-Writ-Session",
            "K9",
            "a",
        ] {
            let key = TrailerKey::new(raw).expect(raw);
            assert_eq!(key.as_str(), raw);
        }
    }

    #[test]
    fn trailer_key_rejects_empty() {
        assert_eq!(TrailerKey::new(""), Err(TrailerKeyError::Empty));
    }

    #[test]
    fn trailer_key_rejects_leading_digit_or_dash() {
        let leading_digit = TrailerKey::new("9-foo").unwrap_err();
        assert!(matches!(leading_digit, TrailerKeyError::InvalidStart(_)));
        let leading_dash = TrailerKey::new("-foo").unwrap_err();
        assert!(matches!(leading_dash, TrailerKeyError::InvalidStart(_)));
    }

    #[test]
    fn trailer_key_rejects_colon_space_and_other_bytes() {
        for raw in ["foo:", "foo bar", "foo_bar", "føø", "foo\n"] {
            let err = TrailerKey::new(raw).unwrap_err();
            assert!(
                matches!(err, TrailerKeyError::InvalidByte(_)),
                "expected InvalidByte for {raw:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn trailer_value_accepts_utf8_and_preserves_whitespace() {
        let value = TrailerValue::new("  Octocat <octocat@example.com>  ").unwrap();
        assert_eq!(value.as_str(), "  Octocat <octocat@example.com>  ");
        let utf8 = TrailerValue::new("Ångström <a@example.com>").unwrap();
        assert_eq!(utf8.as_str(), "Ångström <a@example.com>");
    }

    #[test]
    fn trailer_value_rejects_empty() {
        assert_eq!(TrailerValue::new(""), Err(TrailerValueError::Empty));
    }

    #[test]
    fn trailer_value_rejects_control_bytes() {
        for raw in ["line\nfeed", "carriage\rreturn", "nul\0byte"] {
            assert_eq!(
                TrailerValue::new(raw),
                Err(TrailerValueError::ContainsControlByte),
                "{raw:?} should be rejected",
            );
        }
    }

    fn valid_key_strategy() -> impl Strategy<Value = String> {
        // Pin a small finite generator: 1 leading ASCII letter, 0..=15
        // body bytes from the alnum+dash alphabet. Keeps shrinking
        // tractable without ceding coverage of the validation rule.
        let leading = "[A-Za-z]";
        let body = "[A-Za-z0-9-]{0,15}";
        (leading, body).prop_map(|(a, b)| format!("{a}{b}"))
    }

    fn valid_value_strategy() -> impl Strategy<Value = String> {
        // Reject the three control bytes; otherwise accept arbitrary
        // non-empty unicode. `prop_filter_map` keeps the constraint
        // visible at the strategy site.
        ".{1,32}".prop_filter_map("contains control bytes", |s| {
            if s.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
                None
            } else {
                Some(s)
            }
        })
    }

    proptest! {
        #[test]
        fn trailer_key_round_trips_for_valid_alphabet(raw in valid_key_strategy()) {
            let key = TrailerKey::new(raw.clone()).expect("strategy produces valid keys");
            prop_assert_eq!(key.as_str(), raw);
        }

        #[test]
        fn trailer_value_round_trips_for_valid_inputs(raw in valid_value_strategy()) {
            let value = TrailerValue::new(raw.clone()).expect("strategy produces valid values");
            prop_assert_eq!(value.as_str(), raw);
        }

        #[test]
        fn trailer_value_always_rejects_control_bytes(
            prefix in ".{0,8}",
            ctrl in prop::sample::select(vec!['\n', '\r', '\0']),
            suffix in ".{0,8}",
        ) {
            let raw = format!("{prefix}{ctrl}{suffix}");
            prop_assert_eq!(
                TrailerValue::new(raw),
                Err(TrailerValueError::ContainsControlByte),
            );
        }
    }
}
