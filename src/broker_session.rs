//! Parsing and validation for the `writd broker` subcommand (the broker-in-VM
//! placement; see `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
//!
//! The host launcher hands a broker VM two pieces of per-session runtime
//! material: a small JSON **session spec** (which session, which agent subnet,
//! where to listen) and a **bearer-token file**. This module is the
//! parse-don't-validate boundary for both — interior code receives typed,
//! validated values, never raw strings. The broker port carried by the spec is
//! the listener fact; it is range-checked against the `vm_http` config at the
//! call site (a policy guardrail), not here.

use std::net::Ipv4Addr;
use std::path::Path;

use crate::core::{BrokerPort, Ipv4Cidr, SessionId};
use crate::vm_http::{VmHttpBearerToken, VmHttpConfigError};

/// A validated broker session spec. Constructed only via [`BrokerSessionSpec::parse_json`]
/// / [`BrokerSessionSpec::read_file`], so interior code gets typed fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BrokerSessionSpec {
    pub session_id: SessionId,
    pub agent_ipv4_cidr: Ipv4Cidr,
    pub bind_addr: Ipv4Addr,
    /// The fixed broker port; range-checked against the configured `vm_http`
    /// port range at the call site, not here.
    pub broker_port: u16,
}

/// The only session-spec schema version this broker understands. A spec at any
/// other version is refused up front (see [`BrokerSessionSpec::parse_json`]) with
/// a clean [`BrokerSessionSpecError::UnsupportedVersion`] — never an opaque
/// unknown-field parse error — so a version-skewed host↔broker pair fails loudly
/// and fast. Bump this in lockstep with the wire schema and
/// [`crate::broker_protocol::BROKER_PROTOCOL_VERSION`].
pub const SUPPORTED_SESSION_SPEC_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBrokerSessionSpec {
    version: u32,
    session_id: String,
    agent_ipv4_cidr: String,
    bind_addr: String,
    broker_port: u16,
}

/// A tolerant envelope read *before* the strict body: it recovers only the
/// `version`, so a spec at a newer version (which will carry fields this broker
/// does not know) is refused as a clean [`BrokerSessionSpecError::UnsupportedVersion`]
/// rather than tripping the body's `deny_unknown_fields`. Deliberately not
/// `deny_unknown_fields` itself — it must parse a future document far enough to
/// read its version.
#[derive(serde::Deserialize)]
struct SessionSpecVersion {
    version: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerSessionSpecError {
    #[error("cannot read session spec {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("session spec is not valid JSON: {0}")]
    Json(serde_json::Error),
    #[error(
        "unsupported session spec version {0}: this broker speaks a different \
         session-spec schema; rebuild the broker image"
    )]
    UnsupportedVersion(u32),
    #[error("session spec session_id is invalid: {0}")]
    SessionId(String),
    #[error("session spec agent_ipv4_cidr {raw:?} is invalid: {reason}")]
    Cidr { raw: String, reason: String },
    #[error("session spec bind_addr {0:?} is not a valid IPv4 address")]
    BindAddr(String),
    #[error("session spec broker_port must be non-zero")]
    ZeroPort,
}

impl BrokerSessionSpec {
    /// Construct a spec host-side (the inverse direction from [`Self::parse_json`],
    /// which the broker VM uses to read it back). Takes a [`BrokerPort`] (not a
    /// raw `u16`) so a zero/privileged port — which `parse_json` would later
    /// reject, breaking the round-trip and failing the broker VM at startup — is
    /// unrepresentable here. The port is still range-checked against the vm_http
    /// config where the spec is consumed.
    pub fn new(
        session_id: SessionId,
        agent_ipv4_cidr: Ipv4Cidr,
        bind_addr: Ipv4Addr,
        broker_port: BrokerPort,
    ) -> Self {
        Self {
            session_id,
            agent_ipv4_cidr,
            bind_addr,
            broker_port: broker_port.get(),
        }
    }

    /// Serialise to the version-1 wire form the broker VM parses with
    /// [`Self::parse_json`]. Round-trips: `parse_json(spec.to_json()) == spec`.
    pub fn to_json(&self) -> String {
        let raw = RawBrokerSessionSpec {
            version: SUPPORTED_SESSION_SPEC_VERSION,
            session_id: self.session_id.to_string(),
            agent_ipv4_cidr: self.agent_ipv4_cidr.to_string(),
            bind_addr: self.bind_addr.to_string(),
            broker_port: self.broker_port,
        };
        serde_json::to_string(&raw).expect("a broker session spec always serialises")
    }

    pub fn parse_json(raw: &str) -> Result<Self, BrokerSessionSpecError> {
        // Gate the version first, from a tolerant envelope: a spec at a newer
        // version (carrying fields we don't know) must surface as a clean version
        // mismatch, not as the strict body's unknown-field error.
        let SessionSpecVersion { version } =
            serde_json::from_str(raw).map_err(BrokerSessionSpecError::Json)?;
        if version != SUPPORTED_SESSION_SPEC_VERSION {
            return Err(BrokerSessionSpecError::UnsupportedVersion(version));
        }
        // The version matches, so the strict, unknown-field-rejecting body parse
        // is a *within-version* guard: a host typo is still caught loudly.
        let raw: RawBrokerSessionSpec =
            serde_json::from_str(raw).map_err(BrokerSessionSpecError::Json)?;
        let session_id = raw
            .session_id
            .parse::<SessionId>()
            .map_err(|e| BrokerSessionSpecError::SessionId(e.to_string()))?;
        let agent_ipv4_cidr = parse_ipv4_cidr(&raw.agent_ipv4_cidr)?;
        let bind_addr = raw
            .bind_addr
            .parse::<Ipv4Addr>()
            .map_err(|_| BrokerSessionSpecError::BindAddr(raw.bind_addr.clone()))?;
        if raw.broker_port == 0 {
            return Err(BrokerSessionSpecError::ZeroPort);
        }
        Ok(Self {
            session_id,
            agent_ipv4_cidr,
            bind_addr,
            broker_port: raw.broker_port,
        })
    }

    pub fn read_file(path: &Path) -> Result<Self, BrokerSessionSpecError> {
        let raw = std::fs::read_to_string(path).map_err(|source| BrokerSessionSpecError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse_json(&raw)
    }
}

fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr, BrokerSessionSpecError> {
    let cidr_err = |reason: &str| BrokerSessionSpecError::Cidr {
        raw: raw.to_string(),
        reason: reason.to_string(),
    };
    let (addr, prefix) = raw
        .split_once('/')
        .ok_or_else(|| cidr_err("missing '/prefix'"))?;
    let addr: Ipv4Addr = addr.parse().map_err(|_| cidr_err("invalid IPv4 address"))?;
    let prefix: u8 = prefix.parse().map_err(|_| cidr_err("invalid prefix"))?;
    Ipv4Cidr::new(addr, prefix).map_err(|e| cidr_err(&e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum BearerTokenFileError {
    #[error("cannot read bearer token file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("bearer token file {0} is empty")]
    Empty(String),
    #[error(
        "bearer token file {0} must be a single line with no interior whitespace \
         (the token is per-session runtime material, not a config field)"
    )]
    Malformed(String),
    #[error("bearer token file {path} contains an invalid token: {source}")]
    Invalid {
        path: String,
        #[source]
        source: VmHttpConfigError,
    },
}

/// Read a per-session bearer token from a file. Strips at most one trailing
/// newline (optionally with a preceding `\r`); any interior whitespace or extra
/// line is an error rather than something to trim, so a mis-injected token fails
/// loudly instead of silently authenticating differently.
pub fn read_bearer_token_file(path: &Path) -> Result<VmHttpBearerToken, BearerTokenFileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| BearerTokenFileError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let token = raw.strip_suffix('\n').unwrap_or(&raw);
    let token = token.strip_suffix('\r').unwrap_or(token);
    if token.is_empty() {
        return Err(BearerTokenFileError::Empty(path.display().to_string()));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(BearerTokenFileError::Malformed(path.display().to_string()));
    }
    VmHttpBearerToken::new(token).map_err(|source| BearerTokenFileError::Invalid {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn valid_spec_json(overrides: &str) -> String {
        format!(
            r#"{{"version":1,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
                 "agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0",
                 "broker_port":18080{overrides}}}"#
        )
    }

    #[test]
    fn parses_a_valid_session_spec() {
        let spec = BrokerSessionSpec::parse_json(&valid_spec_json("")).unwrap();
        assert_eq!(
            spec.session_id,
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
                .parse::<SessionId>()
                .unwrap()
        );
        assert_eq!(
            spec.agent_ipv4_cidr,
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap()
        );
        assert_eq!(spec.bind_addr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(spec.broker_port, 18080);
    }

    #[test]
    fn spec_round_trips_through_json() {
        let spec = BrokerSessionSpec::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
                .parse::<SessionId>()
                .unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv4Addr::UNSPECIFIED,
            BrokerPort::new(18080).unwrap(),
        );
        let parsed = BrokerSessionSpec::parse_json(&spec.to_json()).unwrap();
        assert_eq!(parsed, spec);
    }

    #[test]
    fn rejects_unsupported_version() {
        let json = r#"{"version":2,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":18080}"#;
        assert!(matches!(
            BrokerSessionSpec::parse_json(json),
            Err(BrokerSessionSpecError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{"version":1,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":18080,"surprise":true}"#;
        assert!(matches!(
            BrokerSessionSpec::parse_json(json),
            Err(BrokerSessionSpecError::Json(_))
        ));
    }

    #[test]
    fn newer_version_with_added_field_reports_unsupported_version_not_unknown_field() {
        // A future broker will add fields to the spec alongside a version bump. An
        // older broker reading that spec must report a clean version mismatch (the
        // host turns it into "rebuild the image"), NOT an opaque unknown-field JSON
        // error — so the version gate has to run *before* the strict body parse.
        let json = r#"{"version":2,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":18080,"log_file":"/run/broker/log"}"#;
        assert!(
            matches!(
                BrokerSessionSpec::parse_json(json),
                Err(BrokerSessionSpecError::UnsupportedVersion(2))
            ),
            "got {:?}",
            BrokerSessionSpec::parse_json(json)
        );
    }

    proptest! {
        /// Any version other than the supported one is refused as a clean version
        /// mismatch — regardless of whatever else the document carries, including
        /// fields a future schema might add — because the version gate precedes the
        /// strict body parse. It is never a `Json` body error.
        #[test]
        fn any_other_version_is_unsupported_not_a_body_error(
            version in any::<u32>()
                .prop_filter("not the supported version", |v| *v != SUPPORTED_SESSION_SPEC_VERSION),
            include_extra in any::<bool>(),
        ) {
            let extra = if include_extra { r#","future_field":{"nested":[1,2,3]}"# } else { "" };
            let json = format!(
                r#"{{"version":{version},"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":18080{extra}}}"#
            );
            prop_assert!(
                matches!(
                    BrokerSessionSpec::parse_json(&json),
                    Err(BrokerSessionSpecError::UnsupportedVersion(v)) if v == version
                ),
                "version {version} (extra={include_extra}) -> {:?}",
                BrokerSessionSpec::parse_json(&json)
            );
        }
    }

    #[test]
    fn rejects_bad_session_id() {
        let json = r#"{"version":1,"session_id":"not-a-uuid","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":18080}"#;
        assert!(matches!(
            BrokerSessionSpec::parse_json(json),
            Err(BrokerSessionSpecError::SessionId(_))
        ));
    }

    #[test]
    fn rejects_bad_cidr() {
        for cidr in [
            "192.168.252.0",
            "192.168.252.0/33",
            "192.168.252.5/24",
            "nope/24",
        ] {
            let json = format!(
                r#"{{"version":1,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"{cidr}","bind_addr":"0.0.0.0","broker_port":18080}}"#
            );
            assert!(
                matches!(
                    BrokerSessionSpec::parse_json(&json),
                    Err(BrokerSessionSpecError::Cidr { .. })
                ),
                "cidr {cidr:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_bind_addr_and_zero_port() {
        let bad_addr = r#"{"version":1,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"not-an-ip","broker_port":18080}"#;
        assert!(matches!(
            BrokerSessionSpec::parse_json(bad_addr),
            Err(BrokerSessionSpecError::BindAddr(_))
        ));
        let zero_port = r#"{"version":1,"session_id":"51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d","agent_ipv4_cidr":"192.168.252.0/24","bind_addr":"0.0.0.0","broker_port":0}"#;
        assert!(matches!(
            BrokerSessionSpec::parse_json(zero_port),
            Err(BrokerSessionSpecError::ZeroPort)
        ));
    }

    fn write_token(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn reads_token_stripping_one_trailing_newline() {
        for contents in ["writ-vm-abc123", "writ-vm-abc123\n", "writ-vm-abc123\r\n"] {
            let f = write_token(contents);
            let token = read_bearer_token_file(f.path()).unwrap();
            assert_eq!(token.as_str(), "writ-vm-abc123", "contents {contents:?}");
        }
    }

    #[test]
    fn rejects_empty_token_file() {
        for contents in ["", "\n"] {
            let f = write_token(contents);
            assert!(
                matches!(
                    read_bearer_token_file(f.path()),
                    Err(BearerTokenFileError::Empty(_))
                ),
                "contents {contents:?} should be empty"
            );
        }
    }

    #[test]
    fn rejects_token_with_interior_whitespace_or_extra_lines() {
        for contents in [
            "writ-vm abc",
            "writ-vm-abc\nmore",
            "writ-vm-abc\n\n",
            "writ-vm-abc\textra",
        ] {
            let f = write_token(contents);
            assert!(
                matches!(
                    read_bearer_token_file(f.path()),
                    Err(BearerTokenFileError::Malformed(_))
                ),
                "contents {contents:?} should be malformed"
            );
        }
    }

    #[test]
    fn rejects_token_with_invalid_bytes() {
        // A control byte that survives the whitespace check but is not a valid
        // bearer-token byte must be rejected by VmHttpBearerToken::new.
        let f = write_token("writ-vm-\u{007f}");
        assert!(matches!(
            read_bearer_token_file(f.path()),
            Err(BearerTokenFileError::Invalid { .. })
        ));
    }
}
