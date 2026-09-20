//! Admission evidence for the `ipv4_only_locked_v1` IPv6 profile: the facts
//! the *host* observes about its own platform, and the pure decision over
//! them.
//!
//! Stage D of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`, and deliberately
//! inert: the profile stays closed. [`ConfiguredIpv6Profile::admit`] is
//! unchanged and still refuses `Ipv4OnlyLockedV1`, nothing calls
//! [`ConfiguredIpv6Profile::admit_locked`] yet, and
//! [`crate::agent_vm_lifecycle::Ipv6IsolationMode`] gains no variant, so no
//! session can be running in the mode and the state store cannot say one is.
//! Opening the profile before the locked start path exists (Stage E2) would
//! route a `locked_v1` session down the legacy root prelaunch, which is the
//! one thing the profile promises not to do.
//!
//! Why evidence at all: the design (`docs/design/ipv4-only-network-confinement.md`,
//! "Persistence and compatibility") admits the profile on what the host *is*,
//! not on what the operator spelled. Six facts, each read by the host from a
//! tool it runs itself:
//!
//! | fact | probe | what it rules out |
//! | --- | --- | --- |
//! | PF helper protocol version | `pf-helper protocol-version` | a helper that still takes its bounds from its caller (below Stage C2) |
//! | PF preflight report | `pf-helper preflight` | a main ruleset in which writ's session anchor never decides a packet |
//! | image isolation-ABI label | `container image inspect` | an image built before the guest initializer's handoff contract |
//! | image manifest digest | `container image inspect` | an image the proof has not been run against |
//! | Apple `container` CLI version | `container --version` | a runtime whose guest kernel and vmnet behaviour are unproven |
//! | macOS build | `sw_vers -buildVersion` | an OS whose PF and vmnet behaviour are unproven |
//!
//! The last three are pinned as *whole records* against
//! [`ProvenPlatforms`]: a host enters that list only in the change that
//! records the vertical proof passing on it, so a platform update closes the
//! profile until the proof is re-run. The first three are absolute
//! requirements with no allowlist: no host, however proven, may start a
//! locked session behind a helper that cannot bound it or an anchor that
//! cannot confine it.
//!
//! The label and the CLI line are *self-asserted*, so they are compatibility
//! signals rather than identity — any image can stamp the label. Identity is
//! the resolved manifest digest, which is also what Stage E2's `container
//! run` is given in place of the tag, so the image inspected here is the
//! image started there.

use std::path::Path;
use std::time::Duration;

use writ_guest_init::record::{ISOLATION_ABI_LABEL, ISOLATION_ABI_VERSION};

use crate::agent_vm_firewall::PfPreflightUnclean;
use crate::agent_vm_lifecycle::{
    AgentVmToolPaths, ConfiguredIpv6Profile, ContainerImage, Ipv6IsolationMode, ProcessInvocation,
};
use crate::agent_vm_probe::{BoundedProbe, ProbeRunFailure, run_bounded_probe};

use crate::agent_vm_pf_helper_protocol::{
    PF_HELPER_PREFLIGHT_MAX_BYTES, PF_HELPER_PROTOCOL_MAX_BYTES, PF_HELPER_PROTOCOL_VERSION,
    PfHelperPreflightDoc, PfHelperProtocolDoc,
};

// --- observation -----------------------------------------------------------

/// A fact the host tried to read from one of its own tools, or the reason it
/// could not.
///
/// Every probe is fallible in ways that are not distinguishable from the
/// outside — a wedged tool, a chatty one, a missing one — so "unreadable" is
/// a value rather than an error: the gatherer always produces a complete
/// [`LockedV1RuntimeEvidence`], and the pure decision refuses on it, naming
/// the fact it could not read. There is deliberately no "assume fine when the
/// probe fails" path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observed<T> {
    Read(T),
    Unreadable(ProbeFailure),
}

impl<T> Observed<T> {
    fn as_read(&self) -> Result<&T, ProbeFailure> {
        match self {
            Observed::Read(value) => Ok(value),
            Observed::Unreadable(failure) => Err(*failure),
        }
    }

    /// Chain a parse onto a successful read, keeping the failure otherwise.
    fn and_then<U>(self, parse: impl FnOnce(T) -> Observed<U>) -> Observed<U> {
        match self {
            Observed::Read(value) => parse(value),
            Observed::Unreadable(failure) => Observed::Unreadable(failure),
        }
    }
}

/// Why a probe yielded no fact.
///
/// [`ProbeRunFailure`]'s variants plus [`ProbeFailure::Unparseable`]. The
/// shared runner reports only how the *run* went, because a tool that ran,
/// succeeded, and printed something this host cannot read is a fact about the
/// output; admission refuses on either, so it names them together.
///
/// The detail behind [`ProbeFailure::Spawn`] (the `std::io::Error`) is logged
/// by the runner rather than carried here: this type is part of the pure
/// decision, and an admission refusal names *which* fact was unreadable, not
/// the errno behind it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProbeFailure {
    /// The tool could not be started at all.
    #[error("the probe could not be started")]
    Spawn,
    /// The tool did not exit within the probe's deadline and was killed.
    #[error("the probe did not finish within its deadline")]
    TimedOut,
    /// The tool wrote more than the probe's byte cap and was killed.
    #[error("the probe wrote more output than its cap allows")]
    OutputTooLarge,
    /// The tool exited non-zero, or on a signal.
    #[error("the probe exited unsuccessfully")]
    Failed,
    /// The tool ran and succeeded, but its output is not the document this
    /// host reads.
    #[error("the probe's output is not a document this host can read")]
    Unparseable,
    /// The tool started, but the host lost the ability to supervise it — it
    /// could not be waited on, or its process group could not be killed. The
    /// run's outcome is unknown, which is not a fact.
    #[error("the probe could not be supervised to completion")]
    Unsupervised,
}

impl From<ProbeRunFailure> for ProbeFailure {
    fn from(failure: ProbeRunFailure) -> Self {
        match failure {
            ProbeRunFailure::Spawn => Self::Spawn,
            ProbeRunFailure::TimedOut => Self::TimedOut,
            ProbeRunFailure::OutputTooLarge => Self::OutputTooLarge,
            ProbeRunFailure::Failed => Self::Failed,
            ProbeRunFailure::Unsupervised => Self::Unsupervised,
        }
    }
}

// --- the individual facts ---------------------------------------------------

/// The Apple `container` CLI's self-reported identity, parsed from the one
/// line `container --version` prints.
///
/// Three components rather than one string because the pin is on all three:
/// a rebuild of the same version from a different commit is a different
/// runtime, and the proof was run against exactly one of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerCliVersion {
    version: String,
    build: String,
    commit: String,
}

/// Why `container --version` output was not read as a version.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "not an Apple container version line of the form \
     `container CLI version <version> (build: <build>, commit: <commit>)`"
)]
pub struct ContainerCliVersionParseError;

const CONTAINER_CLI_PREFIX: &str = "container CLI version ";
const CONTAINER_CLI_BUILD_PREFIX: &str = " (build: ";
const CONTAINER_CLI_COMMIT_PREFIX: &str = ", commit: ";
const CONTAINER_CLI_COMPONENT_MAX: usize = 64;

/// One bounded, non-empty component of the version line.
fn component(
    text: &str,
    ok: impl Fn(char) -> bool,
) -> Result<String, ContainerCliVersionParseError> {
    (!text.is_empty() && text.len() <= CONTAINER_CLI_COMPONENT_MAX && text.chars().all(ok))
        .then(|| text.to_string())
        .ok_or(ContainerCliVersionParseError)
}

impl ContainerCliVersion {
    /// Parse the exact line the CLI prints, with or without its trailing
    /// newline. Nothing else is accepted: a line whose shape changed is a
    /// runtime this host has no pin for, which is a refusal and not a guess.
    pub fn parse(stdout: &str) -> Result<Self, ContainerCliVersionParseError> {
        let line = stdout.strip_suffix('\n').unwrap_or(stdout);
        let rest = line
            .strip_prefix(CONTAINER_CLI_PREFIX)
            .ok_or(ContainerCliVersionParseError)?;
        let (version, rest) = rest
            .split_once(CONTAINER_CLI_BUILD_PREFIX)
            .ok_or(ContainerCliVersionParseError)?;
        let (build, rest) = rest
            .split_once(CONTAINER_CLI_COMMIT_PREFIX)
            .ok_or(ContainerCliVersionParseError)?;
        let commit = rest
            .strip_suffix(')')
            .ok_or(ContainerCliVersionParseError)?;
        Ok(Self {
            version: component(version, |c| {
                c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+'
            })?,
            build: component(build, |c| c.is_ascii_alphanumeric() || c == '-')?,
            commit: component(commit, |c| c.is_ascii_digit() || c.is_ascii_lowercase())?,
        })
    }

    /// The line [`Self::parse`] accepts, rebuilt from the parsed components.
    pub fn line(&self) -> String {
        format!(
            "{CONTAINER_CLI_PREFIX}{}{CONTAINER_CLI_BUILD_PREFIX}{}{CONTAINER_CLI_COMMIT_PREFIX}{})",
            self.version, self.build, self.commit
        )
    }
}

impl std::fmt::Display for ContainerCliVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.line())
    }
}

/// A macOS build identifier as `sw_vers -buildVersion` prints it, e.g.
/// `25G72`.
///
/// The build, not the product version: macOS updates change vmnet and PF
/// behaviour without changing the marketing version, and this subsystem's
/// journal records exactly that happening to router-advertisement behaviour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsBuild(String);

/// Why `sw_vers -buildVersion` output was not read as a build.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("not a macOS build identifier (digits, one capital, digits, optional lowercase suffix)")]
pub struct MacOsBuildParseError;

const MACOS_BUILD_MAX: usize = 16;

/// Advance `at` past the longest run of bytes satisfying `ok`, and return how
/// many there were.
fn run_of(bytes: &[u8], at: &mut usize, ok: impl Fn(&u8) -> bool) -> usize {
    let start = *at;
    while *at < bytes.len() && ok(&bytes[*at]) {
        *at += 1;
    }
    *at - start
}

impl MacOsBuild {
    /// Parse the single line `sw_vers -buildVersion` prints, with or without
    /// its trailing newline.
    ///
    /// The grammar is Apple's: the darwin major, one capital, the build
    /// number, and a lowercase suffix on a seed build — `25G72`, `23A5301h`.
    /// Nothing else, so a `sw_vers` that started printing a sentence is an
    /// unreadable fact rather than a build nobody proved anything about.
    pub fn parse(stdout: &str) -> Result<Self, MacOsBuildParseError> {
        let text = stdout.strip_suffix('\n').unwrap_or(stdout);
        if text.is_empty() || text.len() > MACOS_BUILD_MAX {
            return Err(MacOsBuildParseError);
        }
        let bytes = text.as_bytes();
        let mut at = 0;
        let major = run_of(bytes, &mut at, u8::is_ascii_digit);
        let capital = run_of(bytes, &mut at, u8::is_ascii_uppercase);
        let minor = run_of(bytes, &mut at, u8::is_ascii_digit);
        let _seed = run_of(bytes, &mut at, u8::is_ascii_lowercase);
        if major == 0 || capital != 1 || minor == 0 || at != bytes.len() {
            return Err(MacOsBuildParseError);
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MacOsBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A resolved OCI manifest digest, the identity of the image the host will
/// start.
///
/// `sha256` only, lowercase, exactly 64 hex digits: that is what Apple
/// `container` resolves a tag to, and a pin that accepted other spellings of
/// the same bytes would be a pin with slack in it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageDigest(String);

/// Why a string was not read as an image digest.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("not a `sha256:` digest of 64 lowercase hex digits")]
pub struct ImageDigestParseError;

const IMAGE_DIGEST_PREFIX: &str = "sha256:";
const IMAGE_DIGEST_HEX_LEN: usize = 64;

impl ImageDigest {
    pub fn parse(text: &str) -> Result<Self, ImageDigestParseError> {
        let hex = text
            .strip_prefix(IMAGE_DIGEST_PREFIX)
            .ok_or(ImageDigestParseError)?;
        if hex.len() != IMAGE_DIGEST_HEX_LEN
            || !hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            return Err(ImageDigestParseError);
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The isolation ABI an image declares through its [`ISOLATION_ABI_LABEL`]
/// label.
///
/// [`ImageIsolationAbi::Absent`] is its own value rather than an unreadable
/// probe because it has its own meaning and its own remedy: an image built
/// before the guest initializer existed, which is refused as *too old* rather
/// than as unreadable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ImageIsolationAbi {
    /// No variant of the image carries the label.
    Absent,
    /// Every variant carries the label, with this same decimal value.
    Version(u32),
}

impl std::fmt::Display for ImageIsolationAbi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageIsolationAbi::Absent => f.write_str("absent"),
            ImageIsolationAbi::Version(version) => write!(f, "{version}"),
        }
    }
}

// --- the evidence -----------------------------------------------------------

/// Everything the host observed about itself, gathered before any decision.
///
/// A flat record of six independent observations. It is not a proof of
/// anything: [`ConfiguredIpv6Profile::admit_locked`] is the only thing that
/// reads it, and only it can produce a [`LockedV1Admission`].
///
/// The two image facts come from one `container image inspect` run but are
/// separate observations, because they fail separately: a label whose value
/// is not a decimal version leaves the digest perfectly readable, and only
/// the label unreadable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedV1RuntimeEvidence {
    pub helper_protocol: Observed<PfHelperProtocolDoc>,
    pub preflight: Observed<PfHelperPreflightDoc>,
    pub image_isolation_abi: Observed<ImageIsolationAbi>,
    pub image_digest: Observed<ImageDigest>,
    pub container_cli: Observed<ContainerCliVersion>,
    pub macos_build: Observed<MacOsBuild>,
}

/// Which of the six facts an admission refusal is about.
///
/// Every [`LockedV1Refused`] names exactly one, so an operator reading the
/// refusal knows which probe to go and fix.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LockedV1Fact {
    /// Not a fact about the host at all: the configured profile is another
    /// one, so this decision does not apply to it.
    ConfiguredProfile,
    HelperProtocol,
    Preflight,
    ImageIsolationAbi,
    ContainerCli,
    MacOsBuild,
    ImageDigest,
}

/// Why no session may start under `ipv4_only_locked_v1` on this host.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockedV1Refused {
    #[error("the configured IPv6 profile is {0:?}, not ipv4_only_locked_v1")]
    NotLockedProfile(ConfiguredIpv6Profile),

    #[error("the PF helper's protocol version could not be read: {0}")]
    HelperProtocolUnreadable(ProbeFailure),
    #[error(
        "the PF helper speaks protocol version {found}, but the locked profile requires \
         {required}: a helper below {required} takes the pools it validates a session against \
         from its caller, so it does not bound this daemon. Install the helper built from this \
         tree."
    )]
    HelperProtocolVersion { found: u16, required: u16 },

    #[error("the PF preflight report could not be read: {0}")]
    PreflightUnreadable(ProbeFailure),
    #[error("PF on this host does not confine an agent VM, so no profile does: {0}")]
    PreflightUnclean(PfPreflightUnclean),

    #[error("the guest image's isolation-ABI label could not be read: {0}")]
    ImageIsolationAbiUnreadable(ProbeFailure),
    #[error(
        "the guest image declares isolation ABI {found} but the locked profile requires \
         {required}; rebuild the image from this tree"
    )]
    ImageIsolationAbiUnsupported {
        found: ImageIsolationAbi,
        required: u32,
    },

    #[error("the Apple container CLI version could not be read: {0}")]
    ContainerCliUnreadable(ProbeFailure),
    #[error(
        "the locked profile's vertical proof has not been run against Apple container \
         `{0}`, so this host has no proof record"
    )]
    ContainerCliNotProven(ContainerCliVersion),

    #[error("the macOS build could not be read: {0}")]
    MacOsBuildUnreadable(ProbeFailure),
    #[error(
        "the locked profile's vertical proof has not been run against macOS build {0} with \
         this Apple container CLI"
    )]
    MacOsBuildNotProven(MacOsBuild),

    #[error("the guest image's manifest digest could not be read: {0}")]
    ImageDigestUnreadable(ProbeFailure),
    #[error(
        "the locked profile's vertical proof has not been run against guest image {0} on this \
         platform"
    )]
    ImageDigestNotProven(ImageDigest),
}

impl LockedV1Refused {
    /// The one fact this refusal is about.
    pub fn fact(&self) -> LockedV1Fact {
        match self {
            Self::NotLockedProfile(_) => LockedV1Fact::ConfiguredProfile,
            Self::HelperProtocolUnreadable(_) | Self::HelperProtocolVersion { .. } => {
                LockedV1Fact::HelperProtocol
            }
            Self::PreflightUnreadable(_) | Self::PreflightUnclean(_) => LockedV1Fact::Preflight,
            Self::ImageIsolationAbiUnreadable(_) | Self::ImageIsolationAbiUnsupported { .. } => {
                LockedV1Fact::ImageIsolationAbi
            }
            Self::ContainerCliUnreadable(_) | Self::ContainerCliNotProven(_) => {
                LockedV1Fact::ContainerCli
            }
            Self::MacOsBuildUnreadable(_) | Self::MacOsBuildNotProven(_) => {
                LockedV1Fact::MacOsBuild
            }
            Self::ImageDigestUnreadable(_) | Self::ImageDigestNotProven(_) => {
                LockedV1Fact::ImageDigest
            }
        }
    }
}

// --- the allowlist ----------------------------------------------------------

/// One platform the locked profile's vertical proof has been run against.
///
/// A whole record, not three independent pins: the proof is an experiment on
/// one combination, and two facts that were each proven separately were never
/// proven together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenPlatform {
    container_cli: ContainerCliVersion,
    macos_build: MacOsBuild,
    image_digest: ImageDigest,
}

/// Why a proof record's literals did not parse.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProvenPlatformParseError {
    #[error("Apple container CLI version: {0}")]
    ContainerCli(#[from] ContainerCliVersionParseError),
    #[error("macOS build: {0}")]
    MacOsBuild(#[from] MacOsBuildParseError),
    #[error("guest image digest: {0}")]
    ImageDigest(#[from] ImageDigestParseError),
}

impl ProvenPlatform {
    /// Build a record from the three lines a proof run records, parsed by
    /// exactly the parsers the probes use — so an entry the probes could
    /// never produce cannot be written down.
    pub fn parse(
        container_cli: &str,
        macos_build: &str,
        image_digest: &str,
    ) -> Result<Self, ProvenPlatformParseError> {
        Ok(Self {
            container_cli: ContainerCliVersion::parse(container_cli)?,
            macos_build: MacOsBuild::parse(macos_build)?,
            image_digest: ImageDigest::parse(image_digest)?,
        })
    }

    pub fn container_cli(&self) -> &ContainerCliVersion {
        &self.container_cli
    }

    pub fn macos_build(&self) -> &MacOsBuild {
        &self.macos_build
    }

    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }
}

/// The platforms the proof has been run against.
///
/// Read as a trie keyed (CLI, macOS build, image digest): a refusal names the
/// level at which the observed platform left it, so "the CLI is unproven" and
/// "this proven CLI was never proven with that image" are different
/// sentences.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenPlatforms(Vec<ProvenPlatform>);

/// The proof records shipped with this binary, as the literals a proof run
/// writes down.
///
/// Empty. Stage E3 adds the first entry in the same change that records its
/// proof passing on that platform, so the code that *can* admit the profile
/// lands before the profile admits anywhere — and a host that updates its OS,
/// its runtime, or its guest image drops out of the list until the proof is
/// re-run there.
const SHIPPED_PROVEN_PLATFORMS: &[(&str, &str, &str)] = &[];

impl ProvenPlatforms {
    /// The shipped allowlist. Panics if a literal in
    /// `SHIPPED_PROVEN_PLATFORMS` does not parse, which is a bug in this
    /// source file rather than anything about the host.
    pub fn shipped() -> Self {
        Self(
            SHIPPED_PROVEN_PLATFORMS
                .iter()
                .map(|(cli, build, digest)| {
                    ProvenPlatform::parse(cli, build, digest).unwrap_or_else(|error| {
                        panic!("shipped proof record ({cli:?}, {build:?}, {digest:?}): {error}")
                    })
                })
                .collect(),
        )
    }

    pub fn new(records: impl IntoIterator<Item = ProvenPlatform>) -> Self {
        Self(records.into_iter().collect())
    }

    pub fn records(&self) -> &[ProvenPlatform] {
        &self.0
    }
}

/// Proof that a host may start a session under `ipv4_only_locked_v1`.
///
/// Only [`ConfiguredIpv6Profile::admit_locked`] constructs one; there is no
/// other constructor and no bypass, so the locked start path (Stage E2)
/// cannot be reached except through the evidence. It carries the proven
/// platform because the start path needs the image *digest* — `container run`
/// is given that, never the tag, so the image admitted here is the image
/// started there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedV1Admission {
    platform: ProvenPlatform,
}

impl LockedV1Admission {
    /// Claim an admission for a platform without gathering the evidence for
    /// it.
    ///
    /// `#[cfg(test)]`, so the production guarantee is intact: nothing outside
    /// a test build can name this, and [`ConfiguredIpv6Profile::admit_locked`]
    /// remains the only way to a `LockedV1Admission`. It exists so the tests
    /// of what a locked session *does* need not first stand up six host
    /// probes' worth of fixtures to reach the code under test.
    #[cfg(test)]
    pub(crate) fn claimed_for_test(platform: ProvenPlatform) -> Self {
        Self { platform }
    }

    pub fn platform(&self) -> &ProvenPlatform {
        &self.platform
    }

    /// The digest of the image this admission is for.
    pub fn image_digest(&self) -> &ImageDigest {
        self.platform.image_digest()
    }
}

/// What a new session may start as, once admission has decided.
///
/// The answer to [`ConfiguredIpv6Profile::admit`], of which
/// [`Ipv6IsolationMode`] is only the part a plan carries. The locked profile
/// needs more than a mode to start under: its launch reads the created
/// container back and refuses any image but the admitted one, so the digest
/// that was admitted has to travel with the decision. Keeping it inside the
/// variant is what stops a locked session being started against an image no
/// evidence named — there is no second way to name one.
///
/// This mirrors [`Ipv6IsolationMode`] variant for variant rather than pairing
/// a mode with an optional admission, so a locked decision without its
/// evidence, or a legacy decision carrying some, cannot be written down.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedProfile {
    DualStackRequired,
    Ipv4OnlyNoGuestIpv6,
    Ipv4OnlyLockedV1(LockedV1Admission),
}

impl AdmittedProfile {
    /// The mode a plan built under this decision carries.
    pub fn ipv6_mode(&self) -> Ipv6IsolationMode {
        match self {
            Self::DualStackRequired => Ipv6IsolationMode::DualStackRequired,
            Self::Ipv4OnlyNoGuestIpv6 => Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            Self::Ipv4OnlyLockedV1(_) => Ipv6IsolationMode::Ipv4OnlyLockedV1,
        }
    }

    /// The evidence this session starts under, for the locked profile alone.
    ///
    /// The start path dispatches on this rather than on the mode, so the arm
    /// that runs the locked sequence is the arm that holds the admission.
    pub fn locked(&self) -> Option<&LockedV1Admission> {
        match self {
            Self::DualStackRequired | Self::Ipv4OnlyNoGuestIpv6 => None,
            Self::Ipv4OnlyLockedV1(admission) => Some(admission),
        }
    }
}

impl ConfiguredIpv6Profile {
    /// Decide whether a new session may start under `ipv4_only_locked_v1` on
    /// the host these observations came from.
    ///
    /// Pure, and total over the evidence: every unreadable fact is a refusal
    /// naming that fact, and there is no combination of failures that admits.
    /// Facts are checked in a fixed order — the two that say "this host
    /// cannot confine a VM at all" first, then the image's self-assertion,
    /// then the proof record — so a host with several problems is told about
    /// the most fundamental one.
    ///
    /// This does not replace [`ConfiguredIpv6Profile::admit`], which still
    /// refuses `Ipv4OnlyLockedV1` outright: until Stage E2 there is no locked
    /// start path for an admission to lead to, and nothing calls this.
    pub fn admit_locked(
        self,
        evidence: &LockedV1RuntimeEvidence,
        allowlist: &ProvenPlatforms,
    ) -> Result<LockedV1Admission, LockedV1Refused> {
        use LockedV1Refused::*;

        if self != ConfiguredIpv6Profile::Ipv4OnlyLockedV1 {
            return Err(NotLockedProfile(self));
        }

        let helper = evidence
            .helper_protocol
            .as_read()
            .map_err(HelperProtocolUnreadable)?;
        if helper.version() != PF_HELPER_PROTOCOL_VERSION {
            return Err(HelperProtocolVersion {
                found: helper.version(),
                required: PF_HELPER_PROTOCOL_VERSION,
            });
        }

        let preflight = evidence.preflight.as_read().map_err(PreflightUnreadable)?;
        if let Some(unclean) = preflight.report().unclean() {
            return Err(PreflightUnclean(unclean));
        }

        let abi = evidence
            .image_isolation_abi
            .as_read()
            .map_err(ImageIsolationAbiUnreadable)?;
        if *abi != ImageIsolationAbi::Version(ISOLATION_ABI_VERSION) {
            return Err(ImageIsolationAbiUnsupported {
                found: *abi,
                required: ISOLATION_ABI_VERSION,
            });
        }

        let cli = evidence
            .container_cli
            .as_read()
            .map_err(ContainerCliUnreadable)?;
        let by_cli: Vec<&ProvenPlatform> = allowlist
            .records()
            .iter()
            .filter(|record| record.container_cli() == cli)
            .collect();
        if by_cli.is_empty() {
            return Err(ContainerCliNotProven(cli.clone()));
        }

        let build = evidence
            .macos_build
            .as_read()
            .map_err(MacOsBuildUnreadable)?;
        let by_build: Vec<&ProvenPlatform> = by_cli
            .into_iter()
            .filter(|record| record.macos_build() == build)
            .collect();
        if by_build.is_empty() {
            return Err(MacOsBuildNotProven(build.clone()));
        }

        let digest = evidence
            .image_digest
            .as_read()
            .map_err(ImageDigestUnreadable)?;
        let Some(platform) = by_build
            .into_iter()
            .find(|record| record.image_digest() == digest)
        else {
            return Err(ImageDigestNotProven(digest.clone()));
        };

        Ok(LockedV1Admission {
            platform: platform.clone(),
        })
    }
}

// --- the probes, as data ----------------------------------------------------

/// Where `sw_vers` lives on macOS. Not configurable: it is part of the OS
/// whose build it reports, and a `sw_vers` found on `PATH` would be a fact
/// about the daemon's environment rather than about the platform.
pub const SW_VERS_PATH: &str = "/usr/bin/sw_vers";

/// Byte cap on `container image inspect` output. Generous next to the ~2 KiB
/// a single-variant image prints, and still a bound: the daemon parses this
/// document, so it must not be able to grow without limit.
pub const IMAGE_INSPECT_MAX_BYTES: usize = 256 * 1024;

/// Byte cap on the two one-line probes (`container --version`,
/// `sw_vers -buildVersion`).
pub const VERSION_LINE_MAX_BYTES: usize = 256;

/// Deadline for the probes that only read local state.
pub const FAST_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for the probes that go through the Apple `container` daemon,
/// which resolves an image and can be slow on a cold start.
pub const CONTAINER_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// The five commands the gatherer runs, projected as data before any of them
/// runs — so what the daemon will execute as root is inspectable, and the
/// tests can assert it without a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedV1ProbePlan {
    pub helper_protocol: BoundedProbe,
    pub preflight: BoundedProbe,
    pub image_inspect: BoundedProbe,
    pub container_cli: BoundedProbe,
    pub macos_build: BoundedProbe,
}

impl LockedV1ProbePlan {
    /// Build the plan for one host.
    ///
    /// The helper is invoked through `sudo`, exactly as the install and
    /// removal are: the point of the probe is to learn about the helper the
    /// daemon will actually use, and that is the privileged one.
    pub fn new(tools: &AgentVmToolPaths, sw_vers: &Path, image: &ContainerImage) -> Self {
        let helper = |subcommand: &str| {
            ProcessInvocation::new(
                tools.sudo(),
                [
                    tools.pf_helper().as_os_str().to_os_string(),
                    std::ffi::OsString::from(subcommand),
                ],
            )
        };
        Self {
            helper_protocol: BoundedProbe {
                invocation: helper("protocol-version"),
                byte_cap: PF_HELPER_PROTOCOL_MAX_BYTES,
                timeout: FAST_PROBE_TIMEOUT,
            },
            preflight: BoundedProbe {
                invocation: helper("preflight"),
                byte_cap: PF_HELPER_PREFLIGHT_MAX_BYTES,
                timeout: FAST_PROBE_TIMEOUT,
            },
            image_inspect: BoundedProbe {
                invocation: ProcessInvocation::new(
                    tools.container(),
                    ["image", "inspect", image.as_str()],
                ),
                byte_cap: IMAGE_INSPECT_MAX_BYTES,
                timeout: CONTAINER_PROBE_TIMEOUT,
            },
            container_cli: BoundedProbe {
                invocation: ProcessInvocation::new(tools.container(), ["--version"]),
                byte_cap: VERSION_LINE_MAX_BYTES,
                timeout: CONTAINER_PROBE_TIMEOUT,
            },
            macos_build: BoundedProbe {
                invocation: ProcessInvocation::new(sw_vers, ["-buildVersion"]),
                byte_cap: VERSION_LINE_MAX_BYTES,
                timeout: FAST_PROBE_TIMEOUT,
            },
        }
    }

    /// The plan a daemon configured with these tools would run, with
    /// `sw_vers` at its fixed OS location.
    pub fn for_host(tools: &AgentVmToolPaths, image: &ContainerImage) -> Self {
        Self::new(tools, Path::new(SW_VERS_PATH), image)
    }

    /// Every probe, in the order [`gather_locked_v1_evidence`] runs them.
    pub fn probes(&self) -> [&BoundedProbe; 5] {
        [
            &self.helper_protocol,
            &self.preflight,
            &self.image_inspect,
            &self.container_cli,
            &self.macos_build,
        ]
    }

    /// [`Self::probes`], mutably: for a caller that wants to change every
    /// probe's cap or deadline without restating the list.
    pub fn probes_mut(&mut self) -> [&mut BoundedProbe; 5] {
        [
            &mut self.helper_protocol,
            &mut self.preflight,
            &mut self.image_inspect,
            &mut self.container_cli,
            &mut self.macos_build,
        ]
    }
}

// --- the gatherer -----------------------------------------------------------

/// Run every probe and return what was observed.
///
/// Infallible by construction: a probe that cannot be spawned, hangs, floods
/// its cap, exits non-zero, or prints something unreadable contributes an
/// [`Observed::Unreadable`] and nothing else. The decision that follows is
/// then a pure function of a complete record, and there is no path on which a
/// failed probe is treated as a satisfied one.
///
/// Sequential, not concurrent: two of the five go through `sudo` to a helper
/// that reads PF state, and five host tools racing for a decision that runs
/// once per session start buys nothing worth the interleaving.
pub async fn gather_locked_v1_evidence(plan: &LockedV1ProbePlan) -> LockedV1RuntimeEvidence {
    let helper_protocol = run_probe(&plan.helper_protocol)
        .await
        .and_then(|stdout| parse_or_unreadable(&stdout, PfHelperProtocolDoc::parse));
    let preflight = run_probe(&plan.preflight)
        .await
        .and_then(|stdout| parse_or_unreadable(&stdout, PfHelperPreflightDoc::parse));
    let (image_isolation_abi, image_digest) = match run_probe(&plan.image_inspect).await {
        Observed::Unreadable(failure) => {
            (Observed::Unreadable(failure), Observed::Unreadable(failure))
        }
        Observed::Read(stdout) => match ImageInspection::parse(&stdout) {
            Err(_) => (
                Observed::Unreadable(ProbeFailure::Unparseable),
                Observed::Unreadable(ProbeFailure::Unparseable),
            ),
            Ok(inspection) => (
                match inspection.isolation_abi {
                    Some(abi) => Observed::Read(abi),
                    None => Observed::Unreadable(ProbeFailure::Unparseable),
                },
                Observed::Read(inspection.digest),
            ),
        },
    };
    let container_cli = run_probe(&plan.container_cli)
        .await
        .and_then(|stdout| parse_or_unreadable(&stdout, ContainerCliVersion::parse));
    let macos_build = run_probe(&plan.macos_build)
        .await
        .and_then(|stdout| parse_or_unreadable(&stdout, MacOsBuild::parse));

    LockedV1RuntimeEvidence {
        helper_protocol,
        preflight,
        image_isolation_abi,
        image_digest,
        container_cli,
        macos_build,
    }
}

fn parse_or_unreadable<T, E>(text: &str, parse: impl FnOnce(&str) -> Result<T, E>) -> Observed<T> {
    match parse(text) {
        Ok(value) => Observed::Read(value),
        Err(_) => Observed::Unreadable(ProbeFailure::Unparseable),
    }
}

/// Run one probe and record what it said, or why it said nothing.
///
/// The run policy — process group, deadline, byte cap, what counts as
/// success — is [`run_bounded_probe`]'s, shared with the guest record
/// channel. All this adds is the vocabulary the decision is written in:
/// a failed run is an [`Observed::Unreadable`] fact rather than an error,
/// because the gatherer always produces a complete evidence record.
async fn run_probe(probe: &BoundedProbe) -> Observed<String> {
    match run_bounded_probe(probe, "locked-profile admission probe").await {
        Ok(stdout) => Observed::Read(stdout),
        Err(failure) => Observed::Unreadable(failure.into()),
    }
}

// --- `container image inspect` ----------------------------------------------

/// What the host reads out of one `container image inspect` document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageInspection {
    /// `None` when the variants disagree about the label, or one carries a
    /// value that is not a decimal version — neither of which names a single
    /// ABI, so neither is a fact.
    pub isolation_abi: Option<ImageIsolationAbi>,
    /// The resolved manifest digest: the image's identity, and what a later
    /// `container run` is given in place of the tag.
    pub digest: ImageDigest,
}

/// Why an inspect document was not read.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ImageInspectParseError {
    #[error("`container image inspect` output is not the expected JSON document")]
    Malformed,
    #[error("`container image inspect` named {0} images; a start needs exactly one")]
    NotExactlyOneImage(usize),
    #[error("`container image inspect` reported an image with no variants")]
    NoVariants,
    #[error("the image's resolved digest is unreadable: {0}")]
    Digest(#[from] ImageDigestParseError),
}

mod wire {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    /// Apple's `container image inspect` document, as much of it as the host
    /// reads. Unknown fields are allowed deliberately: this is a tool whose
    /// output grows across releases, and refusing an image because the CLI
    /// added a field would fail closed for no security reason. The fields
    /// that *are* read are read exactly.
    #[derive(Deserialize)]
    pub(super) struct Image {
        pub(super) configuration: Configuration,
        pub(super) variants: Vec<Variant>,
    }

    #[derive(Deserialize)]
    pub(super) struct Configuration {
        pub(super) descriptor: Descriptor,
    }

    #[derive(Deserialize)]
    pub(super) struct Descriptor {
        pub(super) digest: String,
    }

    #[derive(Deserialize)]
    pub(super) struct Variant {
        pub(super) config: VariantConfig,
    }

    #[derive(Deserialize)]
    pub(super) struct VariantConfig {
        pub(super) config: Option<OciConfig>,
    }

    #[derive(Deserialize)]
    pub(super) struct OciConfig {
        #[serde(rename = "Labels")]
        pub(super) labels: Option<BTreeMap<String, String>>,
    }
}

impl ImageInspection {
    /// Parse the document `container image inspect <image>` prints.
    ///
    /// The label must agree across every architecture variant: a multi-arch
    /// image whose arm64 variant is current and whose amd64 variant is stale
    /// declares no single ABI, and picking one of them would be choosing
    /// which half of the image to believe.
    pub fn parse(stdout: &str) -> Result<Self, ImageInspectParseError> {
        let images: Vec<wire::Image> =
            serde_json::from_str(stdout).map_err(|_| ImageInspectParseError::Malformed)?;
        let [image] = <[wire::Image; 1]>::try_from(images)
            .map_err(|images| ImageInspectParseError::NotExactlyOneImage(images.len()))?;
        if image.variants.is_empty() {
            return Err(ImageInspectParseError::NoVariants);
        }
        let digest = ImageDigest::parse(&image.configuration.descriptor.digest)?;

        let mut labels = image.variants.iter().map(|variant| {
            variant
                .config
                .config
                .as_ref()
                .and_then(|config| config.labels.as_ref())
                .and_then(|labels| labels.get(ISOLATION_ABI_LABEL))
                .map(String::as_str)
        });
        let first = labels.next().expect("variants is non-empty");
        let agreed = labels.all(|label| label == first);
        let isolation_abi = if !agreed {
            None
        } else {
            match first {
                None => Some(ImageIsolationAbi::Absent),
                // `u32::from_str` accepts `+1` and leading zeroes; the label
                // this host stamps is exactly the decimal, so accept exactly
                // that and nothing else.
                Some(value) => is_canonical_decimal(value)
                    .then(|| value.parse().ok())
                    .flatten()
                    .map(ImageIsolationAbi::Version),
            }
        };
        Ok(Self {
            isolation_abi,
            digest,
        })
    }
}

/// Whether a string is a `u32` written the one way this host writes it:
/// ASCII digits, no sign, no leading zero unless the value is zero.
fn is_canonical_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

#[cfg(test)]
mod tests;
