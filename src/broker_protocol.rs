//! The host↔broker version handshake.
//!
//! The `broker_placement = vm` arm boots a broker VM whose image bakes in a full
//! `writd` binary (it runs `writd broker`). The host `writd` and that in-VM
//! `writd` are the *same* binary built from the *same* source tree, and are only
//! ever meant to be built together. When they diverge — most commonly a rebuilt
//! host against a stale image — the broker can reject a CLI flag the host now
//! passes, or otherwise misread the host's material, and the only symptom used to
//! be an opaque 180s readiness timeout.
//!
//! This module gives the broker a way to *report* its protocol version to the
//! host: the broker stamps [`BROKER_PROTOCOL_VERSION`] into its ready file (a
//! [`BrokerReadyDoc`]), and the host refuses a mismatch with an actionable
//! "rebuild the image" error. It catches the *non-crashing* skew class; a broker
//! too old to even parse the host's argv dies before it can write anything and is
//! caught by the liveness check in [`crate::broker_vm_runner`] instead.
//!
//! See `docs/plans/2026-07-01-broker-image-version-handshake.md`.

use serde::{Deserialize, Serialize};

/// The host↔broker protocol version. **Bump this** whenever the broker's
/// contract with the host changes in a way that requires the broker VM image to
/// be rebuilt:
///
/// - the `writd broker` CLI arguments (see [`crate::broker_entrypoint::BrokerArgs`]),
/// - the session-spec schema ([`crate::broker_session::BrokerSessionSpec`]),
/// - the ready-file schema ([`BrokerReadyDoc`]),
/// - the slice of daemon config the broker reads.
///
/// A CI test (`broker_contract_fingerprint_is_pinned`) derives a structural
/// fingerprint of that contract and fails when it changes, so a contract change
/// that forgets to bump this constant is caught at CI, before an image is built.
pub const BROKER_PROTOCOL_VERSION: u32 = 1;

/// The synthetic version assigned to a *legacy* bare-port ready file — one
/// written by a pre-handshake broker image. It is distinct from every real
/// [`BROKER_PROTOCOL_VERSION`] (which starts at 1), so such an image always
/// mismatches and surfaces as a clean "rebuild the image" error rather than an
/// opaque parse failure.
pub const LEGACY_PROTOCOL_VERSION: u32 = 0;

/// The document the broker atomically writes to its ready file once it is
/// serving, and the host parses to (a) confirm readiness and (b) gate the
/// protocol version.
///
/// Deliberately *not* `deny_unknown_fields`: an older host reading a newer
/// broker's doc must still recover `protocol_version` (and report the mismatch)
/// rather than fail to parse. Forward-compatibility here mirrors the session
/// spec's tolerance of unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerReadyDoc {
    /// The broker's compiled [`BROKER_PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The port the broker bound. The host cross-checks this against the port it
    /// told the broker to use.
    pub broker_port: u16,
    /// Human-facing build identifier (e.g. the crate version), for diagnostics
    /// only — **never** the compatibility gate, since dev trees are dirty and a
    /// build hash is not a reliable equality key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writd_build: Option<String>,
}

/// Failure to parse a broker ready file into a [`BrokerReadyDoc`].
#[derive(Debug, thiserror::Error)]
pub enum BrokerReadyDocError {
    #[error("broker ready file is empty")]
    Empty,
    #[error("broker ready file is neither the versioned JSON document nor a legacy bare port: {0}")]
    Malformed(String),
}

impl BrokerReadyDoc {
    /// Build the doc the current broker publishes: this binary's protocol version
    /// and build string, plus the bound port.
    pub fn current(broker_port: u16) -> Self {
        Self {
            protocol_version: BROKER_PROTOCOL_VERSION,
            broker_port,
            writd_build: Some(concat!("writd ", env!("CARGO_PKG_VERSION")).to_string()),
        }
    }

    /// Serialise to the on-disk ready-file form: single-line JSON plus a trailing
    /// newline (matching the broker's atomic-write convention).
    pub fn to_ready_file(&self) -> String {
        // A plain struct of a u32, u16, and optional string never fails to
        // serialise.
        format!(
            "{}\n",
            serde_json::to_string(self).expect("BrokerReadyDoc serialises")
        )
    }

    /// Parse the ready-file contents. Accepts the versioned JSON document, and
    /// also the *legacy* bare-integer port form written by pre-handshake brokers
    /// — mapping the latter to [`LEGACY_PROTOCOL_VERSION`] so a stale image
    /// surfaces as a clean version mismatch rather than a parse error.
    pub fn parse(contents: &str) -> Result<Self, BrokerReadyDocError> {
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Err(BrokerReadyDocError::Empty);
        }
        if let Ok(doc) = serde_json::from_str::<BrokerReadyDoc>(trimmed) {
            return Ok(doc);
        }
        if let Ok(port) = trimmed.parse::<u16>() {
            return Ok(Self {
                protocol_version: LEGACY_PROTOCOL_VERSION,
                broker_port: port,
                writd_build: None,
            });
        }
        Err(BrokerReadyDocError::Malformed(
            trimmed.chars().take(200).collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn current_stamps_the_compiled_version() {
        let doc = BrokerReadyDoc::current(18085);
        assert_eq!(doc.protocol_version, BROKER_PROTOCOL_VERSION);
        assert_eq!(doc.broker_port, 18085);
        assert!(doc.writd_build.is_some());
    }

    #[test]
    fn legacy_bare_port_parses_as_version_zero() {
        // The exact form a pre-handshake broker wrote: "<port>\n".
        let doc = BrokerReadyDoc::parse("18085\n").unwrap();
        assert_eq!(doc.protocol_version, LEGACY_PROTOCOL_VERSION);
        assert_eq!(doc.broker_port, 18085);
        assert_eq!(doc.writd_build, None);
        // ...and 0 always mismatches a real version, so the gate fires.
        assert_ne!(doc.protocol_version, BROKER_PROTOCOL_VERSION);
    }

    #[test]
    fn empty_and_garbage_are_rejected() {
        assert!(matches!(
            BrokerReadyDoc::parse("   \n"),
            Err(BrokerReadyDocError::Empty)
        ));
        assert!(matches!(
            BrokerReadyDoc::parse("not a port and not json"),
            Err(BrokerReadyDocError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_fields_are_tolerated_and_version_recovered() {
        // A newer broker's doc with an extra field must still yield the version so
        // the host can report the mismatch (not fail to parse).
        let doc =
            BrokerReadyDoc::parse(r#"{"protocol_version":7,"broker_port":18085,"future":true}"#)
                .unwrap();
        assert_eq!(doc.protocol_version, 7);
        assert_eq!(doc.broker_port, 18085);
    }

    proptest! {
        /// The on-disk form round-trips: parsing what the broker writes yields the
        /// same document.
        #[test]
        fn ready_doc_round_trips(
            protocol_version in any::<u32>(),
            broker_port in any::<u16>(),
            writd_build in proptest::option::of(".*"),
        ) {
            let doc = BrokerReadyDoc { protocol_version, broker_port, writd_build };
            let parsed = BrokerReadyDoc::parse(&doc.to_ready_file()).unwrap();
            prop_assert_eq!(parsed, doc);
        }

        /// Any bare u16 is read as a legacy (version-0) doc carrying that port.
        #[test]
        fn bare_port_is_legacy(port in any::<u16>()) {
            let doc = BrokerReadyDoc::parse(&format!("{port}\n")).unwrap();
            prop_assert_eq!(doc.protocol_version, LEGACY_PROTOCOL_VERSION);
            prop_assert_eq!(doc.broker_port, port);
        }
    }
}
