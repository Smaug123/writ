//! The PF helper's documents: the bounded JSON lines the privileged helper
//! answers with, and the host-side parsers that read them.
//!
//! The helper renders them; the daemon (from Stage D of the
//! `ipv4_only_locked_v1` plan) parses the probe and the preflight report as
//! admission evidence, and the locked start path (Stage E2) parses the install
//! report. Both directions live here so the two binaries cannot drift: each
//! parser accepts *exactly* the strings its renderer produces (optionally
//! followed by the single newline `println!` adds), and nothing else — no
//! trailing data, no second object, no unknown protocol name, no non-canonical
//! spelling of the same object.
//!
//! Three documents:
//! - [`PfHelperProtocolDoc`], the answer to `protocol-version`;
//! - [`PfHelperPreflightDoc`], the answer to `preflight`: the host-local PF
//!   facts an install is conditional on, read without loading anything;
//! - [`PfHelperInstallReportDoc`], what a successful `install` prints: the
//!   anchor whose readback matched, the interfaces it was resolved to, and the
//!   last phase completed.
//!
//! Version 2 is what the shipped helper speaks, and it *means* the whole of
//! Stage C2's boundary: the pools and broker-port range come from the
//! root-owned policy file rather than the caller, every load is read back and
//! compared exactly with the intent, and the interfaces are resolved again
//! after the load. Version 1 is the helper before any of that, which still
//! took its bounds from the unprivileged caller; the daemon's
//! `ipv4_only_locked_v1` admission requires 2.

use serde::{Deserialize, Serialize};

use crate::agent_vm_firewall::{
    PassTranslationRule, PfInstallPhase, PfPreflightReport, SessionAnchorPlacement,
    SessionFirewallReport,
};
use crate::agent_vm_pf_helper_policy::{PfHelperPolicy, parse_ipv4_cidr, parse_ipv6_cidr};
use crate::core::{AgentNetworkPool, BrokerPortRange, PfAnchorName, PfInterface, SessionId};

/// The protocol name every helper document carries.
pub const PF_HELPER_PROTOCOL_NAME: &str = "writ-agent-vm-pf-helper";

/// The protocol version the helper built from this tree reports.
pub const PF_HELPER_PROTOCOL_VERSION: u16 = 2;

/// Maximum `protocol-version` response the host reads: the trust boundary's
/// fixed byte cap, applied before any parsing.
pub const PF_HELPER_PROTOCOL_MAX_BYTES: usize = 256;

/// Maximum `preflight` response the host reads. The report quotes the main
/// ruleset lines ahead of the session anchor and every `pass` translation rule
/// loaded, so it grows with the host's PF configuration; a host whose report
/// does not fit is one whose PF state the daemon cannot vouch for.
pub const PF_HELPER_PREFLIGHT_MAX_BYTES: usize = 16 * 1024;

/// Maximum `install` report the host reads: one anchor path and a handful of
/// interface names.
pub const PF_HELPER_INSTALL_REPORT_MAX_BYTES: usize = 4096;

/// Why a helper response was refused.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfHelperProtocolParseError {
    /// The response exceeds the document's byte cap.
    #[error("PF helper response exceeds {0} bytes")]
    TooLarge(usize),
    /// The response is not the canonical single-object document.
    #[error("PF helper response is malformed")]
    Malformed,
    /// The document names a protocol other than [`PF_HELPER_PROTOCOL_NAME`].
    #[error("PF helper response names an unknown protocol")]
    UnsupportedProtocol,
    /// The document claims a protocol version this parser does not read.
    #[error("PF helper response claims unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    /// Something follows the one object (a second object, or any other bytes).
    #[error("PF helper response has trailing data after the object")]
    TrailingData,
}

/// The `protocol` and `version` fields every wire object starts with.
trait WireHeader {
    fn protocol(&self) -> &str;
    fn version(&self) -> u16;
}

/// Read one bounded, canonical, single-object document.
///
/// `cap` is checked before anything is parsed; the object must start at byte
/// 0; exactly one value is read with a streaming deserializer so "a second
/// object follows" and "the first object is broken" are told apart; the
/// protocol name and version are checked; and finally the parsed document is
/// re-rendered and required to equal the input byte for byte, so the same
/// JSON value spelled differently is refused: it is not something the helper
/// emits, so it is not something the host accepts.
fn parse_exact<'a, W, D>(
    response: &'a str,
    cap: usize,
    accept_version: impl FnOnce(u16) -> bool,
    from_wire: impl FnOnce(W) -> Result<D, PfHelperProtocolParseError>,
    render: impl FnOnce(&D) -> String,
) -> Result<D, PfHelperProtocolParseError>
where
    W: Deserialize<'a> + WireHeader,
{
    use PfHelperProtocolParseError::*;
    if response.len() > cap {
        return Err(TooLarge(cap));
    }
    let body = response.strip_suffix('\n').unwrap_or(response);
    if !body.starts_with('{') {
        return Err(Malformed);
    }
    let mut stream = serde_json::Deserializer::from_str(body).into_iter::<W>();
    let wire = match stream.next() {
        Some(Ok(wire)) => wire,
        Some(Err(_)) | None => return Err(Malformed),
    };
    if wire.protocol() != PF_HELPER_PROTOCOL_NAME {
        return Err(UnsupportedProtocol);
    }
    if !accept_version(wire.version()) {
        return Err(UnsupportedVersion(wire.version()));
    }
    if stream.byte_offset() != body.len() {
        return Err(TrailingData);
    }
    let doc = from_wire(wire)?;
    if render(&doc) != body {
        return Err(Malformed);
    }
    Ok(doc)
}

fn render_wire<W: Serialize>(wire: &W) -> String {
    serde_json::to_string(wire)
        .expect("wire structs of strings, numbers, and lists always serialise")
}

// --- protocol-version ------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolWire<'a> {
    protocol: &'a str,
    version: u16,
}

impl WireHeader for ProtocolWire<'_> {
    fn protocol(&self) -> &str {
        self.protocol
    }
    fn version(&self) -> u16 {
        self.version
    }
}

/// A parsed `protocol-version` answer from the PF helper.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PfHelperProtocolDoc {
    version: u16,
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
        render_wire(&ProtocolWire {
            protocol: PF_HELPER_PROTOCOL_NAME,
            version: self.version,
        })
    }

    /// Parse a captured response. Accepts exactly [`Self::render`]'s output,
    /// optionally followed by one `\n`. Any version is accepted: this is the
    /// document the host reads *to learn* the version.
    pub fn parse(response: &str) -> Result<Self, PfHelperProtocolParseError> {
        parse_exact(
            response,
            PF_HELPER_PROTOCOL_MAX_BYTES,
            |_| true,
            |wire: ProtocolWire<'_>| {
                Ok(Self {
                    version: wire.version,
                })
            },
            |doc| doc.render(),
        )
    }
}

// --- preflight --------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightWire<'a> {
    protocol: &'a str,
    version: u16,
    policy: PolicyWire,
    pf_enabled: bool,
    session_anchor: AnchorPlacementWire,
    pass_translation_rules: Vec<TranslationRuleWire>,
}

/// The bounds the helper loaded from its policy file, so the daemon can check
/// they are the pools and range it allocates from.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    ipv4_pool: String,
    ipv6_pool: String,
    broker_port_min: u16,
    broker_port_max: u16,
}

impl WireHeader for PreflightWire<'_> {
    fn protocol(&self) -> &str {
        self.protocol
    }
    fn version(&self) -> u16 {
        self.version
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "placement", rename_all = "snake_case", deny_unknown_fields)]
enum AnchorPlacementWire {
    First,
    Preceded { lines: Vec<String> },
    Absent,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationRuleWire {
    anchor: Option<String>,
    rule: String,
}

/// A parsed `preflight` answer: the [`PfPreflightReport`] the helper read,
/// and the [`PfHelperPolicy`] it loaded to read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfHelperPreflightDoc {
    report: PfPreflightReport,
    policy: PfHelperPolicy,
}

impl PfHelperPreflightDoc {
    pub fn new(report: PfPreflightReport, policy: PfHelperPolicy) -> Self {
        Self { report, policy }
    }

    pub fn report(&self) -> &PfPreflightReport {
        &self.report
    }

    pub fn policy(&self) -> PfHelperPolicy {
        self.policy
    }

    /// Render as one line without a trailing newline.
    pub fn render(&self) -> String {
        let session_anchor = match &self.report.session_anchor {
            SessionAnchorPlacement::First => AnchorPlacementWire::First,
            SessionAnchorPlacement::Preceded(lines) => AnchorPlacementWire::Preceded {
                lines: lines.clone(),
            },
            SessionAnchorPlacement::Absent => AnchorPlacementWire::Absent,
        };
        render_wire(&PreflightWire {
            protocol: PF_HELPER_PROTOCOL_NAME,
            version: PF_HELPER_PROTOCOL_VERSION,
            policy: PolicyWire {
                ipv4_pool: self.policy.pool().ipv4_base().to_string(),
                ipv6_pool: self.policy.pool().ipv6_base().to_string(),
                broker_port_min: self.policy.broker_port_range().min().get(),
                broker_port_max: self.policy.broker_port_range().max().get(),
            },
            pf_enabled: self.report.pf_enabled,
            session_anchor,
            pass_translation_rules: self
                .report
                .pass_translation_rules
                .iter()
                .map(|rule| TranslationRuleWire {
                    anchor: rule.anchor.clone(),
                    rule: rule.rule.clone(),
                })
                .collect(),
        })
    }

    /// Parse a captured response. Accepts exactly [`Self::render`]'s output
    /// for the current protocol version, optionally followed by one `\n`.
    pub fn parse(response: &str) -> Result<Self, PfHelperProtocolParseError> {
        parse_exact(
            response,
            PF_HELPER_PREFLIGHT_MAX_BYTES,
            |version| version == PF_HELPER_PROTOCOL_VERSION,
            |wire: PreflightWire<'_>| {
                let session_anchor = match wire.session_anchor {
                    AnchorPlacementWire::First => SessionAnchorPlacement::First,
                    AnchorPlacementWire::Preceded { lines } => {
                        SessionAnchorPlacement::Preceded(lines)
                    }
                    AnchorPlacementWire::Absent => SessionAnchorPlacement::Absent,
                };
                use PfHelperProtocolParseError::Malformed;
                let pool = AgentNetworkPool::new(
                    parse_ipv4_cidr(&wire.policy.ipv4_pool).map_err(|_| Malformed)?,
                    parse_ipv6_cidr(&wire.policy.ipv6_pool).map_err(|_| Malformed)?,
                )
                .map_err(|_| Malformed)?;
                let broker_port_range =
                    BrokerPortRange::new(wire.policy.broker_port_min, wire.policy.broker_port_max)
                        .map_err(|_| Malformed)?;
                Ok(Self {
                    policy: PfHelperPolicy::new(pool, broker_port_range),
                    report: PfPreflightReport {
                        pf_enabled: wire.pf_enabled,
                        session_anchor,
                        pass_translation_rules: wire
                            .pass_translation_rules
                            .into_iter()
                            .map(|rule| PassTranslationRule {
                                anchor: rule.anchor,
                                rule: rule.rule,
                            })
                            .collect(),
                    },
                })
            },
            |doc| doc.render(),
        )
    }
}

// --- install report ---------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallReportWire<'a> {
    protocol: &'a str,
    version: u16,
    anchor: String,
    interfaces: Vec<String>,
    phase: &'a str,
}

impl WireHeader for InstallReportWire<'_> {
    fn protocol(&self) -> &str {
        self.protocol
    }
    fn version(&self) -> u16 {
        self.version
    }
}

/// A parsed `install` report: the session anchor whose readback matched the
/// intended ruleset, the interfaces the attached anchor was resolved to (empty
/// for the pre-attach install), and the last install phase that completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfHelperInstallReportDoc {
    session_id: SessionId,
    interfaces: Vec<PfInterface>,
    phase: PfInstallPhase,
}

impl PfHelperInstallReportDoc {
    /// The document a successful install prints: every phase completed.
    pub fn verified(report: &SessionFirewallReport) -> Self {
        Self {
            session_id: report.session_id(),
            interfaces: report.interfaces().to_vec(),
            phase: PfInstallPhase::Reresolve,
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn anchor(&self) -> PfAnchorName {
        PfAnchorName::for_session(self.session_id)
    }

    pub fn interfaces(&self) -> &[PfInterface] {
        &self.interfaces
    }

    pub fn phase(&self) -> PfInstallPhase {
        self.phase
    }

    /// Render as one line without a trailing newline.
    pub fn render(&self) -> String {
        render_wire(&InstallReportWire {
            protocol: PF_HELPER_PROTOCOL_NAME,
            version: PF_HELPER_PROTOCOL_VERSION,
            anchor: self.anchor().as_str().to_string(),
            interfaces: self
                .interfaces
                .iter()
                .map(|iface| iface.as_str().to_string())
                .collect(),
            phase: self.phase.as_str(),
        })
    }

    /// Parse a captured response. Accepts exactly [`Self::render`]'s output
    /// for the current protocol version, optionally followed by one `\n`.
    pub fn parse(response: &str) -> Result<Self, PfHelperProtocolParseError> {
        use PfHelperProtocolParseError::Malformed;
        parse_exact(
            response,
            PF_HELPER_INSTALL_REPORT_MAX_BYTES,
            |version| version == PF_HELPER_PROTOCOL_VERSION,
            |wire: InstallReportWire<'_>| {
                let session_id = wire
                    .anchor
                    .strip_prefix("writ/session/")
                    .and_then(|id| id.parse::<SessionId>().ok())
                    .ok_or(Malformed)?;
                let interfaces = wire
                    .interfaces
                    .into_iter()
                    .map(|name| PfInterface::new(name).map_err(|_| Malformed))
                    .collect::<Result<Vec<_>, _>>()?;
                let phase = PfInstallPhase::ALL
                    .into_iter()
                    .find(|phase| phase.as_str() == wire.phase)
                    .ok_or(Malformed)?;
                Ok(Self {
                    session_id,
                    interfaces,
                    phase,
                })
            },
            |doc| doc.render(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Independent oracle for "is `s` exactly a rendered protocol document":
    /// the grammar `{"protocol":"writ-agent-vm-pf-helper","version":<u16
    /// decimal>}` with no leading zeros and nothing else.
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
    fn current_document_is_the_pinned_v2_line() {
        assert_eq!(
            PfHelperProtocolDoc::current().render(),
            r#"{"protocol":"writ-agent-vm-pf-helper","version":2}"#
        );
        assert_eq!(PfHelperProtocolDoc::current().version(), 2);
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
                Err(PfHelperProtocolParseError::TooLarge(PF_HELPER_PROTOCOL_MAX_BYTES))
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

        // --- preflight ---

        #[test]
        fn preflight_parse_inverts_render(report in arb_preflight_report()) {
            let doc = PfHelperPreflightDoc::new(report, test_policy());
            let rendered = doc.render();
            prop_assert!(!rendered.contains(['\n', '\r']));
            prop_assert_eq!(PfHelperPreflightDoc::parse(&rendered), Ok(doc.clone()));
            prop_assert_eq!(PfHelperPreflightDoc::parse(&format!("{rendered}\n")), Ok(doc));
        }

        /// Whatever the preflight parser accepts, it accepts as exactly one
        /// rendering: inputs are rendered documents with random byte edits.
        #[test]
        fn preflight_accepts_only_its_own_renderings((text, edited) in arb_edited_preflight()) {
            match PfHelperPreflightDoc::parse(&text) {
                Ok(doc) => prop_assert_eq!(doc.render(), text.clone()),
                Err(err) => prop_assert!(edited, "an unedited document was refused: {err}"),
            }
        }

        #[test]
        fn preflight_refuses_any_other_version(
            report in arb_preflight_report(),
            version in any::<u16>().prop_filter("must differ", |v| *v != PF_HELPER_PROTOCOL_VERSION),
        ) {
            let rendered = PfHelperPreflightDoc::new(report, test_policy()).render();
            let current = format!(r#""version":{PF_HELPER_PROTOCOL_VERSION},"#);
            prop_assert!(rendered.contains(&current));
            let other = rendered.replacen(&current, &format!(r#""version":{version},"#), 1);
            prop_assert_eq!(
                PfHelperPreflightDoc::parse(&other),
                Err(PfHelperProtocolParseError::UnsupportedVersion(version))
            );
        }

        #[test]
        fn preflight_over_the_cap_is_too_large(lines in 1usize..4, width in 0usize..256) {
            // Enough anchor lines to cross the cap, each well-formed: size is
            // refused before content is looked at.
            let line = "a".repeat(PF_HELPER_PREFLIGHT_MAX_BYTES / lines + width);
            let report = PfPreflightReport {
                pf_enabled: true,
                session_anchor: SessionAnchorPlacement::Preceded(vec![line; lines]),
                pass_translation_rules: Vec::new(),
            };
            let rendered = PfHelperPreflightDoc::new(report, test_policy()).render();
            prop_assert!(rendered.len() > PF_HELPER_PREFLIGHT_MAX_BYTES);
            prop_assert_eq!(
                PfHelperPreflightDoc::parse(&rendered),
                Err(PfHelperProtocolParseError::TooLarge(PF_HELPER_PREFLIGHT_MAX_BYTES))
            );
        }

        // --- install report ---

        #[test]
        fn install_report_parse_inverts_render(doc in arb_install_report()) {
            let rendered = doc.render();
            prop_assert!(rendered.len() <= PF_HELPER_INSTALL_REPORT_MAX_BYTES);
            prop_assert!(!rendered.contains(['\n', '\r']));
            prop_assert_eq!(PfHelperInstallReportDoc::parse(&rendered), Ok(doc.clone()));
            prop_assert_eq!(PfHelperInstallReportDoc::parse(&format!("{rendered}\n")), Ok(doc));
        }

        #[test]
        fn install_report_accepts_only_its_own_renderings((text, edited) in arb_edited_install_report()) {
            match PfHelperInstallReportDoc::parse(&text) {
                Ok(doc) => prop_assert_eq!(doc.render(), text.clone()),
                Err(err) => prop_assert!(edited, "an unedited document was refused: {err}"),
            }
        }
    }

    #[test]
    fn the_verified_report_names_the_anchor_interfaces_and_final_phase() {
        let session_id: SessionId = "0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b".parse().unwrap();
        let report = SessionFirewallReport::new(
            session_id,
            vec![
                PfInterface::new("bridge100").unwrap(),
                PfInterface::new("vmenet0").unwrap(),
            ],
        );
        let doc = PfHelperInstallReportDoc::verified(&report);
        assert_eq!(
            doc.render(),
            r#"{"protocol":"writ-agent-vm-pf-helper","version":2,"anchor":"writ/session/0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b","interfaces":["bridge100","vmenet0"],"phase":"reresolve"}"#
        );
        assert_eq!(doc.phase(), PfInstallPhase::Reresolve);
        assert_eq!(doc.anchor(), report.anchor());
    }

    #[test]
    fn the_preflight_of_a_clean_host_is_the_pinned_line() {
        let doc = PfHelperPreflightDoc::new(
            PfPreflightReport {
                pf_enabled: true,
                session_anchor: SessionAnchorPlacement::First,
                pass_translation_rules: Vec::new(),
            },
            test_policy(),
        );
        assert_eq!(
            doc.render(),
            r#"{"protocol":"writ-agent-vm-pf-helper","version":2,"policy":{"ipv4_pool":"10.200.0.0/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":49152,"broker_port_max":65535},"pf_enabled":true,"session_anchor":{"placement":"first"},"pass_translation_rules":[]}"#
        );
        assert_eq!(doc.report().require_clean().ok(), Some(()));
    }

    /// Both verdicts must be reachable for the edit properties to mean
    /// anything; check the generators actually land on both sides.
    #[test]
    fn the_edited_generators_reach_both_verdicts() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::deterministic();
        let (mut accepted, mut refused) = (0usize, 0usize);
        for _ in 0..1000 {
            let (text, _) = arb_edited_preflight()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            match PfHelperPreflightDoc::parse(&text) {
                Ok(_) => accepted += 1,
                Err(_) => refused += 1,
            }
        }
        assert!(accepted >= 100, "preflight accepted {accepted} of 1000");
        assert!(refused >= 100, "preflight refused {refused} of 1000");
        let (mut accepted, mut refused) = (0usize, 0usize);
        for _ in 0..1000 {
            let (text, _) = arb_edited_install_report()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            match PfHelperInstallReportDoc::parse(&text) {
                Ok(_) => accepted += 1,
                Err(_) => refused += 1,
            }
        }
        assert!(
            accepted >= 100,
            "install report accepted {accepted} of 1000"
        );
        assert!(refused >= 100, "install report refused {refused} of 1000");
    }

    fn test_policy() -> PfHelperPolicy {
        PfHelperPolicy::new(
            AgentNetworkPool::new(
                parse_ipv4_cidr("10.200.0.0/16").unwrap(),
                parse_ipv6_cidr("fd00:7772:6974::/48").unwrap(),
            )
            .unwrap(),
            BrokerPortRange::new(49152, 65535).unwrap(),
        )
    }

    fn arb_line() -> impl Strategy<Value = String> {
        // pf.conf rule text as pfctl prints it: printable ASCII, and the odd
        // quote or backslash that JSON has to escape.
        "[ -~]{0,60}"
    }

    fn arb_preflight_report() -> impl Strategy<Value = PfPreflightReport> {
        (
            any::<bool>(),
            prop_oneof![
                Just(SessionAnchorPlacement::First),
                prop::collection::vec(arb_line(), 1..4).prop_map(SessionAnchorPlacement::Preceded),
                Just(SessionAnchorPlacement::Absent),
            ],
            prop::collection::vec(
                (prop::option::of("[a-z./]{1,20}"), arb_line())
                    .prop_map(|(anchor, rule)| PassTranslationRule { anchor, rule }),
                0..3,
            ),
        )
            .prop_map(|(pf_enabled, session_anchor, pass_translation_rules)| {
                PfPreflightReport {
                    pf_enabled,
                    session_anchor,
                    pass_translation_rules,
                }
            })
    }

    fn arb_install_report() -> impl Strategy<Value = PfHelperInstallReportDoc> {
        (
            any::<u128>(),
            prop::collection::vec("[a-zA-Z][a-zA-Z0-9]{0,14}", 0..4),
            prop::sample::select(PfInstallPhase::ALL.to_vec()),
        )
            .prop_map(|(session, interfaces, phase)| PfHelperInstallReportDoc {
                session_id: SessionId::from_uuid(uuid::Uuid::from_u128(session)),
                interfaces: interfaces
                    .into_iter()
                    .map(|name| PfInterface::new(name).unwrap())
                    .collect(),
                phase,
            })
    }

    /// One byte-level edit: an inserted space, a deleted byte, a case flip,
    /// or a replaced printable byte.
    fn edit(text: String, edit: Option<(prop::sample::Index, u8, u8)>) -> (String, bool) {
        let Some((index, kind, byte)) = edit else {
            return (text, false);
        };
        let mut bytes = text.into_bytes();
        let at = index.index(bytes.len());
        match kind {
            0 => bytes.insert(at, b' '),
            1 => {
                bytes.remove(at);
            }
            2 => bytes[at] = bytes[at].to_ascii_uppercase(),
            _ => bytes[at] = 0x20 + byte % 0x5f,
        }
        (String::from_utf8_lossy(&bytes).into_owned(), true)
    }

    fn arb_edit() -> impl Strategy<Value = Option<(prop::sample::Index, u8, u8)>> {
        prop::option::of((any::<prop::sample::Index>(), 0u8..4, any::<u8>()))
    }

    fn arb_edited_preflight() -> impl Strategy<Value = (String, bool)> {
        (arb_preflight_report(), arb_edit()).prop_map(|(report, e)| {
            edit(PfHelperPreflightDoc::new(report, test_policy()).render(), e)
        })
    }

    fn arb_edited_install_report() -> impl Strategy<Value = (String, bool)> {
        (arb_install_report(), arb_edit()).prop_map(|(doc, e)| edit(doc.render(), e))
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
