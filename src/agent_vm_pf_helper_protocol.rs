//! The PF helper's `protocol-version` document: the one bounded JSON object the
//! privileged helper answers with, and the host-side parser that reads it.
//!
//! The helper renders it; the daemon (from Stage D of the `ipv4_only_locked_v1`
//! plan) parses it as admission evidence. Both directions live here so the two
//! binaries cannot drift: the parser accepts *exactly* the strings the renderer
//! produces (optionally followed by the single newline `println!` adds), and
//! nothing else — no trailing data, no second object, no unknown protocol name,
//! no non-canonical spelling of the same object.
//!
//! Version 1 is what the shipped helper speaks. Version 2 *means* the whole of
//! Stage C2's boundary (policy file, exact readback, re-resolve), so the number
//! only moves once all of that has landed.

use serde::{Deserialize, Serialize};

/// The protocol name every helper document carries.
pub const PF_HELPER_PROTOCOL_NAME: &str = "writ-agent-vm-pf-helper";

/// The protocol version the helper built from this tree reports.
pub const PF_HELPER_PROTOCOL_VERSION: u16 = 1;

/// Maximum `protocol-version` response the host reads: the trust boundary's
/// fixed byte cap, applied before any parsing.
pub const PF_HELPER_PROTOCOL_MAX_BYTES: usize = 256;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<'a> {
    protocol: &'a str,
    version: u16,
}

/// A parsed `protocol-version` answer from the PF helper.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PfHelperProtocolDoc {
    version: u16,
}

/// Why a `protocol-version` response was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfHelperProtocolParseError {
    /// The response exceeds [`PF_HELPER_PROTOCOL_MAX_BYTES`].
    #[error("PF helper protocol response exceeds {PF_HELPER_PROTOCOL_MAX_BYTES} bytes")]
    TooLarge,
    /// The response is not the canonical single-object document.
    #[error("PF helper protocol response is malformed")]
    Malformed,
    /// The document names a protocol other than [`PF_HELPER_PROTOCOL_NAME`].
    #[error("PF helper protocol response names an unknown protocol")]
    UnsupportedProtocol,
    /// Something follows the one object (a second object, or any other bytes).
    #[error("PF helper protocol response has trailing data after the object")]
    TrailingData,
}

impl PfHelperProtocolDoc {
    /// The document the helper built from this tree emits.
    pub fn current() -> Self {
        Self {
            version: PF_HELPER_PROTOCOL_VERSION,
        }
    }

    /// A document claiming an arbitrary version, for the host-side tests that
    /// need to exercise "helper reports v1 / v2 / something else".
    pub fn with_version(version: u16) -> Self {
        Self { version }
    }

    pub fn version(self) -> u16 {
        self.version
    }

    /// Render as one line without a trailing newline.
    pub fn render(self) -> String {
        let wire = Wire {
            protocol: PF_HELPER_PROTOCOL_NAME,
            version: self.version,
        };
        serde_json::to_string(&wire).expect("a two-field struct of str and u16 always serialises")
    }

    /// Parse a captured response. Accepts exactly [`Self::render`]'s output,
    /// optionally followed by one `\n`.
    pub fn parse(response: &str) -> Result<Self, PfHelperProtocolParseError> {
        use PfHelperProtocolParseError::*;
        if response.len() > PF_HELPER_PROTOCOL_MAX_BYTES {
            return Err(TooLarge);
        }
        let body = response.strip_suffix('\n').unwrap_or(response);
        // The object must start at byte 0: `serde_json` would skip leading
        // whitespace, and the canonical check below would catch it, but a
        // response that does not begin with the object is malformed rather
        // than a non-canonical spelling.
        if !body.starts_with('{') {
            return Err(Malformed);
        }
        // Read one value with a streaming deserializer so that "a second object
        // follows" and "the first object is broken" are told apart.
        let mut stream = serde_json::Deserializer::from_str(body).into_iter::<Wire<'_>>();
        let wire = match stream.next() {
            Some(Ok(wire)) => wire,
            Some(Err(_)) | None => return Err(Malformed),
        };
        if wire.protocol != PF_HELPER_PROTOCOL_NAME {
            return Err(UnsupportedProtocol);
        }
        if stream.byte_offset() != body.len() {
            return Err(TrailingData);
        }
        let doc = Self {
            version: wire.version,
        };
        // Exact, not semantic: the same JSON value spelled differently is not
        // something the helper emits, so it is not something the host accepts.
        if doc.render() != body {
            return Err(Malformed);
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Independent oracle for "is `s` exactly a rendered document": the grammar
    /// `{"protocol":"writ-agent-vm-pf-helper","version":<u16 decimal>}` with no
    /// leading zeros and nothing else.
    fn canonical_version(s: &str) -> Option<u16> {
        let body = s.strip_prefix(r#"{"protocol":"writ-agent-vm-pf-helper","version":"#)?;
        let digits = body.strip_suffix('}')?;
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return None;
        }
        digits.parse::<u16>().ok()
    }

    #[test]
    fn current_document_is_the_pinned_v1_line() {
        assert_eq!(
            PfHelperProtocolDoc::current().render(),
            r#"{"protocol":"writ-agent-vm-pf-helper","version":1}"#
        );
        assert_eq!(PfHelperProtocolDoc::current().version(), 1);
    }

    proptest! {
        #[test]
        fn render_is_one_bounded_line(version in any::<u16>()) {
            let rendered = PfHelperProtocolDoc::with_version(version).render();
            prop_assert!(rendered.len() <= PF_HELPER_PROTOCOL_MAX_BYTES);
            prop_assert!(!rendered.contains(['\n', '\r']));
            prop_assert_eq!(canonical_version(&rendered), Some(version));
        }

        #[test]
        fn parse_inverts_render_with_or_without_the_println_newline(version in any::<u16>()) {
            let doc = PfHelperProtocolDoc::with_version(version);
            let rendered = doc.render();
            prop_assert_eq!(PfHelperProtocolDoc::parse(&rendered), Ok(doc));
            prop_assert_eq!(PfHelperProtocolDoc::parse(&format!("{rendered}\n")), Ok(doc));
        }

        /// The parser accepts a string iff it is exactly a rendered document,
        /// optionally with one trailing newline. Inputs mix canonical documents,
        /// documents with junk appended or prepended, near-misses, and noise, so
        /// both sides of the iff are exercised.
        #[test]
        fn parse_accepts_exactly_the_canonical_images(s in input_strategy()) {
            let stripped = s.strip_suffix('\n').unwrap_or(&s);
            let expected = if s.len() > PF_HELPER_PROTOCOL_MAX_BYTES {
                None
            } else {
                canonical_version(stripped).map(PfHelperProtocolDoc::with_version)
            };
            prop_assert_eq!(PfHelperProtocolDoc::parse(&s).ok(), expected, "input {:?}", s);
        }

        #[test]
        fn anything_over_the_byte_cap_is_too_large(
            version in any::<u16>(),
            padding in 0usize..64,
        ) {
            // Even a document that would otherwise be canonical-plus-newline is
            // refused on size before it is looked at.
            let rendered = PfHelperProtocolDoc::with_version(version).render();
            let filler = " ".repeat(PF_HELPER_PROTOCOL_MAX_BYTES + 1 + padding - rendered.len());
            let oversized = format!("{rendered}{filler}");
            prop_assert!(oversized.len() > PF_HELPER_PROTOCOL_MAX_BYTES);
            prop_assert_eq!(
                PfHelperProtocolDoc::parse(&oversized),
                Err(PfHelperProtocolParseError::TooLarge)
            );
        }

        #[test]
        fn a_second_object_or_any_trailing_bytes_is_trailing_data(
            version in any::<u16>(),
            suffix in trailing_suffix(),
        ) {
            let rendered = PfHelperProtocolDoc::with_version(version).render();
            let input = format!("{rendered}{suffix}");
            prop_assume!(input.len() <= PF_HELPER_PROTOCOL_MAX_BYTES);
            prop_assert_eq!(
                PfHelperProtocolDoc::parse(&input),
                Err(PfHelperProtocolParseError::TrailingData),
                "input {:?}", input
            );
        }

        #[test]
        fn an_unknown_protocol_name_is_refused_by_name(
            version in any::<u16>(),
            name in "[a-z][a-z0-9-]{0,40}".prop_filter("must differ", |n| n != PF_HELPER_PROTOCOL_NAME),
        ) {
            let input = format!(r#"{{"protocol":"{name}","version":{version}}}"#);
            prop_assert_eq!(
                PfHelperProtocolDoc::parse(&input),
                Err(PfHelperProtocolParseError::UnsupportedProtocol)
            );
        }

        #[test]
        fn a_non_canonical_spelling_of_a_valid_object_is_malformed(
            version in any::<u16>(),
            variant in 0u8..4,
        ) {
            // Same JSON value, different bytes: the parser is exact, not
            // semantic, so the helper cannot drift into a looser format.
            let input = match variant {
                0 => format!(r#"{{"protocol": "{PF_HELPER_PROTOCOL_NAME}","version":{version}}}"#),
                1 => format!(r#"{{"version":{version},"protocol":"{PF_HELPER_PROTOCOL_NAME}"}}"#),
                2 => format!(r#" {{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":{version}}}"#),
                _ => format!(r#"{{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":{version},"extra":1}}"#),
            };
            prop_assert_eq!(
                PfHelperProtocolDoc::parse(&input),
                Err(PfHelperProtocolParseError::Malformed),
                "input {:?}", input
            );
        }
    }

    fn trailing_suffix() -> impl Strategy<Value = String> {
        prop_oneof![
            // A second object, on the same line or the next.
            any::<u16>().prop_map(|v| PfHelperProtocolDoc::with_version(v).render()),
            any::<u16>()
                .prop_map(|v| format!("\n{}", PfHelperProtocolDoc::with_version(v).render())),
            // Two newlines, a CRLF, whitespace, or arbitrary bytes.
            Just("\n\n".to_string()),
            Just("\r\n".to_string()),
            Just(" ".to_string()),
            Just("\n ".to_string()),
            "[^\n]{1,40}\n?",
        ]
    }

    fn input_strategy() -> impl Strategy<Value = String> {
        let canonical = any::<u16>().prop_map(|v| PfHelperProtocolDoc::with_version(v).render());
        prop_oneof![
            canonical.clone(),
            canonical.clone().prop_map(|c| format!("{c}\n")),
            (canonical.clone(), "[ -~]{0,20}").prop_map(|(c, junk)| format!("{c}{junk}")),
            ("[ -~]{0,20}", canonical.clone()).prop_map(|(junk, c)| format!("{junk}{c}")),
            // Near-misses: a leading zero, a version above u16, an empty version.
            (1u16..10).prop_map(|v| format!(
                r#"{{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":0{v}}}"#
            )),
            (65536u32..70000).prop_map(|v| format!(
                r#"{{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":{v}}}"#
            )),
            Just(format!(
                r#"{{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":}}"#
            )),
            Just(String::new()),
            Just("\n".to_string()),
            "[ -~\n]{0,300}",
        ]
    }
}
