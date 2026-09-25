//! What the guest says during the proof, held as claims.
//!
//! Stage E3b of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`, and evidence
//! protocol rule 2 of `docs/design/ipv4-only-network-confinement.md`: guest
//! output is diagnostics or explicit doubt, never a verdict.
//!
//! Until this stage `scripts/prove-agent-vm-lifecycle.sh` graded directly on
//! what it read from inside the guest: an empty `ip -6 addr`, an absent
//! `/proc/sys/net/ipv6`, a `wget` that exited non-zero. Each of those is a
//! report by the party under test, and a compromised guest can make any of
//! them say whatever passes. So the harness no longer reads the guest at all.
//! It captures each answer, unread, into one file per [`GuestSlot`], and this
//! module is the only thing that looks at them.
//!
//! # What a claim can do here
//!
//! Exactly one thing: withdraw a conclusion the host reached for itself. Each
//! slot has a parser the host wrote, which reads the capture into a
//! [`Claim<bool>`] and from there into a [`Doubt`]; the doubts together
//! can only turn [`SessionVerdict::Proven`] into
//! [`SessionVerdict::Inconclusive`], never the reverse. A guest that reports
//! holding `CAP_NET_RAW` fails the proof. A guest that reports *not* holding it
//! has proved nothing, and the proof's summary does not say it has.
//!
//! Every parser is fail-closed: a capture that is not exactly the shape the
//! guest command prints raises doubt, so a garbled, truncated, or empty answer
//! is inconclusive rather than clean.
//!
//! # Why the report has no fields
//!
//! The report is a total map from [`GuestSlot`] to [`Claim<RawCapture>`], not a
//! struct with one field per question. A guest fact can therefore only be added
//! as a new slot, and a slot's capture is a claim by its type: there is no
//! field to add as a bare value, and a new variant does not compile until
//! [`GuestSlot::doubt`] says how the host reads it.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use crate::agent_vm_claim::{Claim, Doubt, RawCapture, Withheld};

/// The most the harness keeps of any one guest answer, in bytes. The harness
/// truncates at the same bound (`head -c`), and a capture that reaches it is a
/// capture the host did not see all of, which the parsers' exact grammars
/// then refuse.
pub const GUEST_CAPTURE_LIMIT: usize = 64 * 1024;

/// One question the proof asks the guest.
///
/// The harness asks each exactly once, with `guest_report <slot>`, and the
/// command it runs prints the shape this slot's parser reads. The two are kept
/// in step by a test that reads the script.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GuestSlot {
    /// Whether the released workload wrote its marker.
    ReleaseMarker,
    /// PID 1's command line: whether the capability read below is of the
    /// released workload rather than the prelaunch gate or an init shim.
    Pid1Cmdline,
    /// PID 1's `/proc/<pid>/status`: its five capability sets.
    Pid1Status,
    /// Which of the probe tools the guest has.
    ProbeTools,
    /// The guest's IPv6 posture before anything is attempted.
    Ipv6AtStart,
    /// What the guest fetched from the broker: the positive control's own
    /// account, which the host grades on the broker listener's log instead.
    BrokerFetch,
    /// What the guest fetched from the forbidden host port.
    ForbiddenFetch,
    /// What the guest fetched from a public IPv4 address.
    InternetFetch,
    /// Whether a DNS lookup against a public resolver answered.
    DnsLookup,
    /// The guest's IPv6 posture after a root re-enable attempt.
    Ipv6AfterReenable,
}

impl GuestSlot {
    /// Every slot, in the order the harness asks them.
    pub const ALL: [Self; 10] = [
        Self::ReleaseMarker,
        Self::Pid1Cmdline,
        Self::Pid1Status,
        Self::ProbeTools,
        Self::Ipv6AtStart,
        Self::BrokerFetch,
        Self::ForbiddenFetch,
        Self::InternetFetch,
        Self::DnsLookup,
        Self::Ipv6AfterReenable,
    ];

    /// The name the harness passes to `guest_report`, and the capture's file
    /// stem.
    pub fn name(self) -> &'static str {
        match self {
            Self::ReleaseMarker => "release-marker",
            Self::Pid1Cmdline => "pid1-cmdline",
            Self::Pid1Status => "pid1-status",
            Self::ProbeTools => "probe-tools",
            Self::Ipv6AtStart => "ipv6-at-start",
            Self::BrokerFetch => "broker-fetch",
            Self::ForbiddenFetch => "forbidden-fetch",
            Self::InternetFetch => "internet-fetch",
            Self::DnsLookup => "dns-lookup",
            Self::Ipv6AfterReenable => "ipv6-after-reenable",
        }
    }

    /// The slot the harness names `name`, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|slot| slot.name() == name)
    }

    /// Whether this slot's capture gives the host reason to withdraw its
    /// conclusion.
    ///
    /// Each parser answers the question in the direction that can only doubt:
    /// "did the guest say the thing a passing run says?" A guest that did has
    /// raised no doubt, which is not agreement; a guest that did not, or said
    /// something else, has.
    pub fn doubt(self, capture: &Claim<RawCapture>) -> Doubt {
        let parse: fn(&str) -> bool = match self {
            Self::ReleaseMarker => says_released,
            Self::Pid1Cmdline => names_released_workload,
            Self::Pid1Status => holds_no_network_authority,
            Self::ProbeTools => has_every_probe_tool,
            Self::Ipv6AtStart => reports_no_routable_ipv6,
            Self::BrokerFetch => fetched_broker,
            Self::ForbiddenFetch | Self::InternetFetch | Self::DnsLookup => failed,
            Self::Ipv6AfterReenable => reports_no_ipv6_stack,
        };
        capture.interpreted_by(parse).doubt_unless_true()
    }
}

/// The session's verdict, as far as the guest is allowed to affect it.
///
/// The harness reaches its guest-report grading only after every host-graded
/// leg has passed — each one dies on failure — so the conclusion it brings is
/// [`SessionVerdict::Proven`]. The guest's claims can withdraw that and do
/// nothing else.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SessionVerdict {
    /// Every host-graded leg passed, and nothing the guest said doubts it.
    Proven,
    /// A guest claim contradicted what a passing run looks like, or the host
    /// brought no conclusion to begin with. Evidence protocol rule 5:
    /// inconclusive is failure.
    Inconclusive,
}

impl Withheld for SessionVerdict {
    fn withheld() -> Self {
        Self::Inconclusive
    }
}

/// Everything the guest said, one capture per slot.
#[derive(Clone, Debug)]
pub struct GuestReport(BTreeMap<GuestSlot, Claim<RawCapture>>);

/// Why a directory of captures is not a report.
#[derive(Debug, thiserror::Error)]
pub enum GuestReportError {
    #[error("could not read the guest capture {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    /// The harness did not ask this question. Not a doubt: the guest had no
    /// part in it, so it is a harness defect.
    #[error("the harness captured no answer for {0:?}")]
    Missing(&'static str),
    /// The harness asked a question this grader has no parser for, so the
    /// script and [`GuestSlot`] have drifted apart.
    #[error("the harness captured {0:?}, which is not a question the grader knows")]
    Unknown(String),
}

impl GuestReport {
    /// A report from a capture per slot.
    ///
    /// Takes a function rather than a map so that totality is the caller's
    /// obligation by construction: there is no slot it can leave out.
    pub fn new(mut capture: impl FnMut(GuestSlot) -> Claim<RawCapture>) -> Self {
        Self(
            GuestSlot::ALL
                .into_iter()
                .map(|slot| (slot, capture(slot)))
                .collect(),
        )
    }

    /// Reads the harness's capture directory: exactly one `<slot>.txt` per
    /// slot, each read to at most [`GUEST_CAPTURE_LIMIT`] bytes.
    pub fn read_dir(dir: &Path) -> Result<Self, GuestReportError> {
        let read_error = |path: &Path, source| GuestReportError::Read {
            path: path.display().to_string(),
            source,
        };
        for entry in std::fs::read_dir(dir).map_err(|e| read_error(dir, e))? {
            let entry = entry.map_err(|e| read_error(dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let known = GuestSlot::ALL
                .iter()
                .any(|slot| name == format!("{}.txt", slot.name()));
            if !known {
                return Err(GuestReportError::Unknown(name));
            }
        }
        let mut captures = BTreeMap::new();
        for slot in GuestSlot::ALL {
            let path = dir.join(format!("{}.txt", slot.name()));
            let file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(GuestReportError::Missing(slot.name()));
                }
                Err(e) => return Err(read_error(&path, e)),
            };
            let mut bytes = Vec::new();
            file.take(GUEST_CAPTURE_LIMIT as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| read_error(&path, e))?;
            // Lossy on purpose: the guest's bytes are not the host's to
            // refuse, and a replacement character fails every parser's
            // grammar, which is the doubt a garbled answer deserves.
            let text = String::from_utf8_lossy(&bytes);
            captures.insert(
                slot,
                Claim::asserted(RawCapture::capture(&text, GUEST_CAPTURE_LIMIT)),
            );
        }
        Ok(Self(captures))
    }

    /// One slot's capture. Every slot has one: [`GuestReport::new`] and
    /// [`GuestReport::read_dir`] are the only constructors, and both are total.
    pub fn claim(&self, slot: GuestSlot) -> &Claim<RawCapture> {
        &self.0[&slot]
    }
}

/// What grading the guest's report decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestGrading {
    pub verdict: SessionVerdict,
    /// The slots whose doubt alone would withdraw a proven verdict, for the
    /// operator reading a failed run. Diagnostics: the verdict above is what
    /// was decided, and it was decided without reading this.
    pub doubted_by: Vec<GuestSlot>,
}

/// Apply the guest's doubts to the conclusion the host reached for itself.
pub fn grade_guest_report(host: SessionVerdict, report: &GuestReport) -> GuestGrading {
    let doubts = GuestSlot::ALL.map(|slot| (slot, slot.doubt(report.claim(slot))));
    let verdict = Doubt::any(doubts.iter().map(|(_, doubt)| *doubt)).shadowing(host);
    // Each slot asked on its own whether it would withdraw a proven verdict,
    // through the same elimination form: a doubt has no other way out.
    let doubted_by = doubts
        .into_iter()
        .filter(|(_, doubt)| {
            doubt.shadowing(SessionVerdict::Proven) == SessionVerdict::Inconclusive
        })
        .map(|(slot, _)| slot)
        .collect();
    GuestGrading {
        verdict,
        doubted_by,
    }
}

// ---------------------------------------------------------------------------
// The parsers. Each reads exactly what its slot's guest command prints, and
// anything else is doubt.
// ---------------------------------------------------------------------------

/// The lines of a capture, with the one trailing newline a shell `echo` adds.
fn lines(text: &str) -> Vec<&str> {
    text.strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect()
}

/// `release-marker`: the guest polls for the workload's marker and prints
/// `released` or `absent`.
pub(crate) fn says_released(text: &str) -> bool {
    lines(text) == ["released"]
}

/// The marker the lifecycle proof's workload runs under, which PID 1's command
/// line carries while the workload is the loop the harness launched.
pub(crate) const RELEASED_WORKLOAD_MARKER: &str = "lifecycle-released";

/// `pid1-cmdline`: PID 1's `/proc/1/cmdline`, NULs rendered as spaces.
pub(crate) fn names_released_workload(text: &str) -> bool {
    text.contains(RELEASED_WORKLOAD_MARKER)
}

/// Linux capability bit numbers (`include/uapi/linux/capability.h`).
pub(crate) const CAP_NET_ADMIN: u32 = 12;
pub(crate) const CAP_NET_RAW: u32 = 13;

/// The five capability sets `/proc/<pid>/status` renders.
pub(crate) const CAPABILITY_SETS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

/// `pid1-status`: whether each of the five capability sets appears exactly
/// once, as a mask the kernel's format admits, holding neither `NET_ADMIN`
/// nor `NET_RAW`.
///
/// Every set, not only the effective one: a capability that is merely
/// permitted, or still in the bounding set for a file-capability binary to
/// pick up on exec, is authority the workload can still reach.
pub(crate) fn holds_no_network_authority(text: &str) -> bool {
    let mut masks: BTreeMap<&str, u64> = BTreeMap::new();
    for line in lines(text) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !CAPABILITY_SETS.contains(&name) {
            continue;
        }
        let value = value.trim_start_matches('\t');
        if value.is_empty()
            || value.len() > 16
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return false;
        }
        let Ok(mask) = u64::from_str_radix(value, 16) else {
            return false;
        };
        if masks.insert(name, mask).is_some() {
            return false;
        }
    }
    masks.len() == CAPABILITY_SETS.len()
        && masks
            .values()
            .all(|mask| mask & (1 << CAP_NET_ADMIN) == 0 && mask & (1 << CAP_NET_RAW) == 0)
}

/// The tools the probes need. Busybox's `command -v` reports only its first
/// argument, so the guest command asks once per tool and prints each it has.
pub(crate) const PROBE_TOOLS: [&str; 3] = ["ip", "wget", "nslookup"];

/// `probe-tools`: exactly the tools, one per line, in order.
pub(crate) fn has_every_probe_tool(text: &str) -> bool {
    lines(text) == PROBE_TOOLS
}

/// What the IPv6 posture command printed, read to its grammar.
///
/// ```text
/// sysctl present|absent
/// addr-exit <n>
/// addr <line of `ip -6 -o addr show scope global`>   (zero or more)
/// route-exit <n>
/// route <line of `ip -6 route show default`>         (zero or more)
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Ipv6Posture {
    pub sysctl_present: bool,
    pub addr_exit: String,
    pub addrs: usize,
    pub route_exit: String,
    pub routes: usize,
}

pub(crate) fn parse_ipv6_posture(text: &str) -> Option<Ipv6Posture> {
    let mut lines = lines(text).into_iter().peekable();
    let sysctl_present = match lines.next()? {
        "sysctl present" => true,
        "sysctl absent" => false,
        _ => return None,
    };
    let addr_exit = lines.next()?.strip_prefix("addr-exit ")?.to_string();
    let mut addrs = 0;
    while lines.peek().is_some_and(|line| line.starts_with("addr ")) {
        lines.next();
        addrs += 1;
    }
    let route_exit = lines.next()?.strip_prefix("route-exit ")?.to_string();
    let mut routes = 0;
    for line in lines {
        line.strip_prefix("route ")?;
        routes += 1;
    }
    Some(Ipv6Posture {
        sysctl_present,
        addr_exit,
        addrs,
        route_exit,
        routes,
    })
}

/// `ipv6-at-start`: both reads succeeded and found no global address and no
/// default route. The sysctl tree may be present or absent: which is expected
/// depends on the profile, and this slot asks only about routability.
pub(crate) fn reports_no_routable_ipv6(text: &str) -> bool {
    parse_ipv6_posture(text).is_some_and(|posture| {
        posture.addr_exit == "0"
            && posture.route_exit == "0"
            && posture.addrs == 0
            && posture.routes == 0
    })
}

/// `ipv6-after-reenable`: as [`reports_no_routable_ipv6`], and the kernel's
/// IPv6 sysctl tree is absent — the profile this harness launches disables
/// IPv6 on the guest kernel's boot line, so a tree that is present means the
/// disable did not take and the empty reads are only an RA that has not
/// arrived yet.
pub(crate) fn reports_no_ipv6_stack(text: &str) -> bool {
    reports_no_routable_ipv6(text)
        && parse_ipv6_posture(text).is_some_and(|posture| !posture.sysctl_present)
}

/// A probe command's output: `exit <n>` and then whatever it printed.
pub(crate) fn parse_exit(text: &str) -> Option<(i64, &str)> {
    let (first, rest) = text.split_once('\n').unwrap_or((text, ""));
    let status = first.strip_prefix("exit ")?;
    if status.is_empty() || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((status.parse().ok()?, rest))
}

/// What the broker serves, which the harness writes and the guest should echo.
pub(crate) const BROKER_BODY: &str = "broker-ok";

/// `broker-fetch`: the fetch succeeded and returned exactly the broker's body.
pub(crate) fn fetched_broker(text: &str) -> bool {
    parse_exit(text).is_some_and(|(status, body)| status == 0 && lines(body) == [BROKER_BODY])
}

/// `forbidden-fetch`, `internet-fetch`, `dns-lookup`: the probe failed. What
/// it printed on the way is diagnostics; only a well-formed non-zero status
/// raises no doubt.
pub(crate) fn failed(text: &str) -> bool {
    parse_exit(text).is_some_and(|(status, _)| status != 0)
}

#[cfg(test)]
mod tests;
