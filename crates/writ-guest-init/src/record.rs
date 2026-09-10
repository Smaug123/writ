//! The two records the initializer writes to its stdout, as a versioned,
//! single-line, byte-bounded ABI.
//!
//! PID 1's stdout is the container's log stream, which is the only channel the
//! host reads after launch (Apple `container` gives the host `container logs`,
//! not a post-release `exec`). The initializer therefore says everything it
//! has to say on that stream, as one of these records:
//!
//! - [`GuestInitRecord::SecurityReady`], emitted exactly once when the handoff
//!   has completed and the release wait is armed. It is what the host's
//!   release gate waits for, and it carries the isolation ABI version so an
//!   old host refuses a new guest (and the reverse) for the right reason
//!   rather than by timing out. It carries *nothing* derived from the wrapped
//!   workload argv: the record a correct initializer emits is one fixed line
//!   per ABI version, so a workload cannot influence it.
//! - [`GuestInitRecord::HandoffFailed`], emitted instead of `SecurityReady`
//!   when a step fails, so a failure is a bounded line on the same stream
//!   rather than a silent timeout. It names the step that failed and a
//!   bounded, single-line reason. The initializer never `exec`s the workload
//!   after emitting it.
//!
//! Both records are bounded by construction: the reason of a failure is a
//! [`BoundedMessage`], which is single-line and at most [`MAX_MESSAGE_BYTES`]
//! bytes however long the underlying error text was, so a rendered record is
//! always under [`MAX_RECORD_BYTES`]. Parsing is strict: it rejects a second
//! line, trailing tokens, an unknown tag, or an over-long input, so the host
//! never mistakes arbitrary workload log output for a record.

/// The token every record begins with. Distinctive enough that the host can
/// pick a record line out of an interleaved log stream, and unlikely to be
/// produced by accident.
pub const RECORD_PREFIX: &str = "writ-agent-vm-guest-init";

/// The isolation ABI version a correct initializer stamps on its
/// `security-ready` record. Bumped only when the host/guest contract changes;
/// it is the same notion as the image's `org.writ.agent-vm.isolation-abi`
/// label (Stage B3), which is held equal to this.
pub const ISOLATION_ABI_VERSION: u32 = parse_abi_version_file(ISOLATION_ABI_VERSION_FILE);

/// The one place the ABI version is written down: a text file the official
/// image's Nix build reads for its `org.writ.agent-vm.isolation-abi` label,
/// and this crate reads at compile time. One source, so the label the image
/// carries and the number the initializer announces cannot disagree.
const ISOLATION_ABI_VERSION_FILE: &str = include_str!("../isolation-abi-version");

/// Parse the version file at compile time: ASCII digits, no leading zero, one
/// trailing newline, nothing else. A malformed file is a build error, not a
/// runtime surprise.
const fn parse_abi_version_file(text: &str) -> u32 {
    let bytes = text.as_bytes();
    assert!(
        !bytes.is_empty() && bytes[bytes.len() - 1] == b'\n',
        "isolation-abi-version must end in exactly one newline"
    );
    let digits = bytes.len() - 1;
    assert!(digits > 0, "isolation-abi-version is empty");
    assert!(
        digits == 1 || bytes[0] != b'0',
        "isolation-abi-version has a leading zero"
    );
    let mut value: u32 = 0;
    let mut i = 0;
    while i < digits {
        let b = bytes[i];
        assert!(b.is_ascii_digit(), "isolation-abi-version is not decimal");
        value = match value.checked_mul(10) {
            Some(v) => v,
            None => panic!("isolation-abi-version overflows u32"),
        };
        value = match value.checked_add((b - b'0') as u32) {
            Some(v) => v,
            None => panic!("isolation-abi-version overflows u32"),
        };
        i += 1;
    }
    value
}

/// The most bytes a [`BoundedMessage`] keeps. An error reason longer than this
/// is truncated on construction, on a UTF-8 boundary.
pub const MAX_MESSAGE_BYTES: usize = 400;

/// The most bytes a rendered record may occupy (excluding any trailing
/// newline). Every record [`GuestInitRecord::render`] produces is under this,
/// and [`GuestInitRecord::parse`] refuses a longer input unread.
pub const MAX_RECORD_BYTES: usize = 512;

/// A single-line message of bounded length.
///
/// Constructed one of two ways. [`BoundedMessage::new`] is lossy: it accepts
/// any string (an OS error's text, say), replaces every control byte with a
/// space so the result is one line, and truncates to [`MAX_MESSAGE_BYTES`] on
/// a UTF-8 boundary. [`BoundedMessage::parse`] is strict: it accepts only a
/// string that is already a valid bounded message, which is what a rendered
/// record's reason field always is, and errors otherwise. So the emitter can
/// never produce an unbounded record, and the host can never be handed one.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct BoundedMessage(String);

/// Why a string is not already a valid [`BoundedMessage`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedMessageError {
    #[error("message is {len} bytes, over the {MAX_MESSAGE_BYTES}-byte bound")]
    TooLong { len: usize },
    #[error("message contains a control byte at position {position}")]
    ControlByte { position: usize },
}

impl BoundedMessage {
    /// Coerce any string into a bounded, single-line message: control bytes
    /// become spaces, and the result is truncated to [`MAX_MESSAGE_BYTES`] on
    /// a character boundary.
    pub fn new(text: &str) -> Self {
        let sanitized: String = text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        // Truncate to the largest character boundary at or under the bound.
        let mut end = 0;
        for (index, c) in sanitized.char_indices() {
            let next = index + c.len_utf8();
            if next > MAX_MESSAGE_BYTES {
                break;
            }
            end = next;
        }
        Self(sanitized[..end].to_string())
    }

    /// Accept a string iff it is already a valid bounded message: at most
    /// [`MAX_MESSAGE_BYTES`] bytes and free of control bytes.
    pub fn parse(text: &str) -> Result<Self, BoundedMessageError> {
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(BoundedMessageError::TooLong { len: text.len() });
        }
        if let Some(position) = text.chars().position(|c| c.is_control()) {
            return Err(BoundedMessageError::ControlByte { position });
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A record the initializer writes to stdout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestInitRecord {
    /// The handoff completed and the release wait is armed. Carries the ABI
    /// version the initializer implements.
    SecurityReady { abi: u32 },
    /// A handoff step failed; the workload was not started. Names the index of
    /// the failing step in the handoff plan and a bounded reason.
    HandoffFailed {
        step_index: usize,
        message: BoundedMessage,
    },
}

/// The tag word that follows the prefix for [`GuestInitRecord::SecurityReady`].
const TAG_SECURITY_READY: &str = "security-ready";
/// The tag word that follows the prefix for [`GuestInitRecord::HandoffFailed`].
const TAG_HANDOFF_FAILED: &str = "handoff-failed";

/// Why a line is not a [`GuestInitRecord`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecordParseError {
    #[error("input contains a newline; a record is a single line")]
    ContainsNewline,
    #[error("input is {len} bytes, over the {MAX_RECORD_BYTES}-byte bound")]
    TooLong { len: usize },
    #[error("line does not begin with the record prefix {RECORD_PREFIX:?}")]
    MissingPrefix,
    #[error("line has a prefix but no record tag")]
    MissingTag,
    #[error("unknown record tag {0:?}")]
    UnknownTag(String),
    #[error("field {field} is missing")]
    MissingField { field: &'static str },
    #[error("field {field} value {value:?} is not {kind}")]
    BadField {
        field: &'static str,
        value: String,
        kind: &'static str,
    },
    #[error("the {tag} record has trailing data: {rest:?}")]
    TrailingData { tag: &'static str, rest: String },
    #[error("the failure reason is not a bounded message: {0}")]
    BadReason(#[from] BoundedMessageError),
}

impl GuestInitRecord {
    /// The record as one line, without a trailing newline. Always at most
    /// [`MAX_RECORD_BYTES`] bytes.
    pub fn render(&self) -> String {
        match self {
            Self::SecurityReady { abi } => {
                format!("{RECORD_PREFIX} {TAG_SECURITY_READY} abi={abi}")
            }
            Self::HandoffFailed {
                step_index,
                message,
            } => {
                format!(
                    "{RECORD_PREFIX} {TAG_HANDOFF_FAILED} step={step_index} reason={}",
                    message.as_str()
                )
            }
        }
    }

    /// Parse one line into a record, rejecting anything that is not exactly a
    /// rendered record: a second line, an over-long input, a foreign prefix,
    /// an unknown tag, a malformed field, or trailing tokens.
    pub fn parse(line: &str) -> Result<Self, RecordParseError> {
        if line.contains('\n') {
            return Err(RecordParseError::ContainsNewline);
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err(RecordParseError::TooLong { len: line.len() });
        }
        let rest = line
            .strip_prefix(RECORD_PREFIX)
            .ok_or(RecordParseError::MissingPrefix)?;
        let rest = rest
            .strip_prefix(' ')
            .ok_or(RecordParseError::MissingPrefix)?;
        let (tag, body) = match rest.split_once(' ') {
            Some((tag, body)) => (tag, body),
            None => (rest, ""),
        };
        match tag {
            TAG_SECURITY_READY => {
                let abi_token = body
                    .strip_prefix("abi=")
                    .ok_or(RecordParseError::MissingField { field: "abi" })?;
                let (abi_value, trailing) = match abi_token.split_once(' ') {
                    Some((value, trailing)) => (value, Some(trailing)),
                    None => (abi_token, None),
                };
                let abi = abi_value
                    .parse::<u32>()
                    .map_err(|_| RecordParseError::BadField {
                        field: "abi",
                        value: abi_value.to_string(),
                        kind: "a u32",
                    })?;
                if let Some(trailing) = trailing {
                    return Err(RecordParseError::TrailingData {
                        tag: TAG_SECURITY_READY,
                        rest: trailing.to_string(),
                    });
                }
                Ok(Self::SecurityReady { abi })
            }
            TAG_HANDOFF_FAILED => {
                let after_step = body
                    .strip_prefix("step=")
                    .ok_or(RecordParseError::MissingField { field: "step" })?;
                let (step_value, after_step) = after_step
                    .split_once(' ')
                    .ok_or(RecordParseError::MissingField { field: "reason" })?;
                let step_index =
                    step_value
                        .parse::<usize>()
                        .map_err(|_| RecordParseError::BadField {
                            field: "step",
                            value: step_value.to_string(),
                            kind: "a usize",
                        })?;
                let reason = after_step
                    .strip_prefix("reason=")
                    .ok_or(RecordParseError::MissingField { field: "reason" })?;
                let message = BoundedMessage::parse(reason)?;
                Ok(Self::HandoffFailed {
                    step_index,
                    message,
                })
            }
            "" => Err(RecordParseError::MissingTag),
            other => Err(RecordParseError::UnknownTag(other.to_string())),
        }
    }
}

/// The one line a correct initializer emits when it is ready for release,
/// spelled out so a reader can see it without running anything. Held equal to
/// [`GuestInitRecord::SecurityReady`] with the current ABI version by a test.
pub const SECURITY_READY_LINE: &str = "writ-agent-vm-guest-init security-ready abi=1";

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The spelled-out ready line is exactly what the record renders, so the
    /// ABI has one definition a reviewer can read.
    #[test]
    fn the_ready_line_is_the_spelled_out_constant() {
        let record = GuestInitRecord::SecurityReady {
            abi: ISOLATION_ABI_VERSION,
        };
        assert_eq!(render_bounded(&record), SECURITY_READY_LINE);
        assert_eq!(GuestInitRecord::parse(SECURITY_READY_LINE), Ok(record));
        assert_eq!(ISOLATION_ABI_VERSION, 1);
    }

    #[test]
    fn the_version_file_is_the_canonical_spelling_of_the_constant() {
        // The Nix image build trims this file and stamps it into the label, so
        // the file must be exactly the decimal the constant parses to, plus a
        // newline: any other bytes would make the label and the record differ.
        assert_eq!(
            ISOLATION_ABI_VERSION_FILE,
            format!("{ISOLATION_ABI_VERSION}\n")
        );
    }

    /// Render, asserting the byte bound the ABI promises, so a change that
    /// blows the bound fails here rather than at the host's bounded read.
    fn render_bounded(record: &GuestInitRecord) -> String {
        let line = record.render();
        assert!(
            line.len() <= MAX_RECORD_BYTES,
            "record renders to {} bytes, over the {MAX_RECORD_BYTES} bound: {line:?}",
            line.len()
        );
        assert!(!line.contains('\n'), "a record is a single line: {line:?}");
        line
    }

    fn arb_message() -> impl Strategy<Value = BoundedMessage> {
        // Any string at all, including control bytes and text far over the
        // bound: `new` must tame all of it.
        prop_oneof![
            any::<String>(),
            "[\\x00-\\x7f]{0,600}",
            "reason=.* step= abi=".prop_map(|s| s.repeat(30)),
        ]
        .prop_map(|s| BoundedMessage::new(&s))
    }

    fn arb_record() -> impl Strategy<Value = GuestInitRecord> {
        prop_oneof![
            any::<u32>().prop_map(|abi| GuestInitRecord::SecurityReady { abi }),
            (any::<usize>(), arb_message()).prop_map(|(step_index, message)| {
                GuestInitRecord::HandoffFailed {
                    step_index,
                    message,
                }
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// `new` bounds and flattens *any* input: at most the byte bound, on a
        /// character boundary (still valid UTF-8), and free of control bytes.
        #[test]
        fn new_bounds_and_flattens_any_input(raw in any::<String>()) {
            let message = BoundedMessage::new(&raw);
            prop_assert!(message.as_str().len() <= MAX_MESSAGE_BYTES);
            prop_assert!(message.as_str().chars().all(|c| !c.is_control()));
            // A bounded message is always re-acceptable by the strict parser.
            prop_assert_eq!(BoundedMessage::parse(message.as_str()), Ok(message));
        }

        /// A message already within bounds and single-line is preserved by
        /// `new` unchanged: the coercion only touches what it must.
        #[test]
        fn new_preserves_an_already_valid_message(
            text in "[ -~]{0,400}",
        ) {
            let message = BoundedMessage::new(&text);
            prop_assert_eq!(message.as_str(), &text);
        }

        /// Render then parse is the identity for every record.
        #[test]
        fn render_then_parse_is_identity(record in arb_record()) {
            let line = render_bounded(&record);
            prop_assert_eq!(GuestInitRecord::parse(&line), Ok(record));
        }

        /// The ready record carries nothing from the wrapped workload argv: a
        /// correct initializer emits one fixed line per ABI version, whatever
        /// it was asked to run. Modelled by asserting the rendered ready line
        /// is independent of an arbitrary argv.
        #[test]
        fn the_ready_record_is_independent_of_the_wrapped_argv(
            _argv in proptest::collection::vec(any::<String>(), 0..8),
        ) {
            let record = GuestInitRecord::SecurityReady { abi: ISOLATION_ABI_VERSION };
            prop_assert_eq!(record.render(), SECURITY_READY_LINE);
        }

        /// Arbitrary text almost never parses as a record, and when it does it
        /// round-trips: parsing is total and never panics.
        #[test]
        fn arbitrary_text_never_panics_and_round_trips_when_it_parses(line in ".*") {
            if let Ok(record) = GuestInitRecord::parse(&line) {
                // A parsed record re-renders to something that parses back
                // equal; the only freedom parse has over render is absent.
                prop_assert_eq!(GuestInitRecord::parse(&record.render()), Ok(record));
            }
        }
    }

    /// Each way a line can fail to be a record, named.
    #[test]
    fn every_rejection_is_specific() {
        use RecordParseError::*;
        let cases: &[(&str, RecordParseError)] = &[
            ("nope", MissingPrefix),
            ("writ-agent-vm-guest-init", MissingPrefix),
            ("writ-agent-vm-guest-init ", MissingTag),
            (
                "writ-agent-vm-guest-init mystery x=1",
                UnknownTag("mystery".to_string()),
            ),
            (
                "writ-agent-vm-guest-init security-ready",
                MissingField { field: "abi" },
            ),
            (
                "writ-agent-vm-guest-init security-ready abi=x",
                BadField {
                    field: "abi",
                    value: "x".to_string(),
                    kind: "a u32",
                },
            ),
            (
                "writ-agent-vm-guest-init security-ready abi=1 extra",
                TrailingData {
                    tag: TAG_SECURITY_READY,
                    rest: "extra".to_string(),
                },
            ),
            (
                "writ-agent-vm-guest-init handoff-failed reason=x",
                MissingField { field: "step" },
            ),
            (
                "writ-agent-vm-guest-init handoff-failed step=2",
                MissingField { field: "reason" },
            ),
            (
                "writ-agent-vm-guest-init handoff-failed step=two reason=x",
                BadField {
                    field: "step",
                    value: "two".to_string(),
                    kind: "a usize",
                },
            ),
            ("line one\nline two", ContainsNewline),
        ];
        for (line, expected) in cases {
            assert_eq!(
                GuestInitRecord::parse(line),
                Err(expected.clone()),
                "{line:?}"
            );
        }
    }

    /// A failure reason with spaces and `=` survives the round trip: the
    /// reason is the whole remainder of the line, not a single token.
    #[test]
    fn a_failure_reason_may_contain_spaces_and_equals() {
        let record = GuestInitRecord::HandoffFailed {
            step_index: 7,
            message: BoundedMessage::new(
                "chown /run/writ-agent-vm: Operation not permitted (os error 1)",
            ),
        };
        let line = render_bounded(&record);
        assert_eq!(GuestInitRecord::parse(&line), Ok(record));
    }

    /// An over-long line is rejected unread rather than parsed.
    #[test]
    fn an_over_long_line_is_rejected() {
        let line = format!(
            "{RECORD_PREFIX} {TAG_HANDOFF_FAILED} step=0 reason={}",
            "x".repeat(MAX_RECORD_BYTES)
        );
        assert!(line.len() > MAX_RECORD_BYTES);
        assert_eq!(
            GuestInitRecord::parse(&line),
            Err(RecordParseError::TooLong { len: line.len() })
        );
    }

    /// A ready line never parses as a failure and vice versa.
    #[test]
    fn the_two_records_are_distinguishable() {
        let ready = GuestInitRecord::SecurityReady { abi: 1 }.render();
        let failed = GuestInitRecord::HandoffFailed {
            step_index: 0,
            message: BoundedMessage::new("boom"),
        }
        .render();
        assert!(matches!(
            GuestInitRecord::parse(&ready),
            Ok(GuestInitRecord::SecurityReady { .. })
        ));
        assert!(matches!(
            GuestInitRecord::parse(&failed),
            Ok(GuestInitRecord::HandoffFailed { .. })
        ));
    }
}
