//! What the vertical proof grades, as a pure function of what the host read.
//!
//! Stage E3a of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`.
//! `scripts/prove-agent-vm-lifecycle.sh` decides whether the host firewall
//! stopped a guest's frames by comparing the session anchor's deny counters
//! either side of a window it timed itself. Until now it did that by scraping
//! `pfctl -vsr` with `awk` of its own; this is the same question asked of
//! Stage C3's typed reading.
//!
//! # Why the typed read is a stronger question
//!
//! The counters of one loaded anchor only rise, and always over the same set
//! of rules. [`PfCounterSnapshot::delta`] therefore refuses two readings whose
//! key sets differ, and refuses one whose counter fell: both mean the anchor
//! was reloaded between the readings, so the two are not readings of one
//! thing and their difference is not a measurement. The `awk` could only ever
//! have subtracted two numbers and got a plausible one.
//!
//! # The one thing a missing rule must not look like
//!
//! An anchor with no interface-scoped deny of the family under test counts
//! nothing, and a rise of nothing satisfies [`DenyExpectation::Unmoved`]
//! perfectly. So does an anchor whose only rule of that label is scoped to no
//! interface — a pairing the helper never files, but one the wire format
//! admits, and the grader reads a file. That is the failure this grading exists to avoid, so the
//! absence of the rule is [`DenyRefusal::NoSuchDeny`] rather than a reading of
//! zero — the same fail-closed move the `awk` made by dying unless at least
//! one rule rendered with a counter.
//!
//! # The other two halves
//!
//! [`listener`] grades the other host-owned fact the proof reads, the access
//! logs of the listeners the host runs. [`guest`] holds what the guest said, as
//! claims that can withdraw a verdict and never reach one (Stage E3b).

pub mod guest;
pub mod listener;

use writ_core::core::{
    IPV4_IFACE_DENY_LABEL, IPV6_IFACE_DENY_LABEL, PfCounterDeltaError, PfCounterSnapshot,
};

/// Which of the session anchor's interface-scoped denies a window is about.
///
/// The anchor installs one deny per family per interface — the guest's bridge
/// and each of its `vmenet` members — and PF may decide a frame on any of
/// them. So a family is a *set* of rules, and what the grading reads is their
/// sum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeniedFamily {
    Ipv4,
    Ipv6,
}

impl DeniedFamily {
    /// The label the session firewall puts on this family's interface-scoped
    /// denies.
    ///
    /// Read from the constants the firewall renders with rather than spelled
    /// again here: a grader that looked for a label nothing emits would find
    /// no rule, and "no rule" is a refusal it could not tell from a genuine
    /// one.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => IPV4_IFACE_DENY_LABEL,
            Self::Ipv6 => IPV6_IFACE_DENY_LABEL,
        }
    }
}

/// What a profile requires of one family's denies across a measured window.
///
/// Inert: it says what the run expects, and [`grade_deny_window`] is what
/// decides whether the reading is that.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DenyExpectation {
    /// The frames were sent and the host stopped them, so the counter must
    /// have risen by at least the number of probes the host commanded. Not
    /// *exactly*: a retrying client and PF's own `block return` accounting
    /// both make the true number a lower bound, and a proof that failed on a
    /// frame it did not command would be measuring the network's chatter.
    RoseByAtLeast(u64),
    /// Nothing could have been sent, so the counter must not have moved at
    /// all. The locked profile's claim: the guest holds no capability that
    /// could emit the frame, so the deny is a backstop that should never be
    /// reached rather than one that should be busy.
    Unmoved,
}

/// What one family's denies counted across the window.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DenyReading {
    /// The summed rise over every interface the family is denied on.
    pub packets: u64,
    /// How many rules that sum is over. Reported because a sum over one
    /// interface and a sum over three are different measurements of the same
    /// number, and an operator reading a failed proof wants to know which.
    pub rules: usize,
}

/// Why a window does not grade.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DenyRefusal {
    /// The two readings are not of one loaded anchor, so their difference is
    /// not a measurement.
    #[error("the two counter readings are not of one loaded anchor: {0}")]
    NotOneAnchor(#[from] PfCounterDeltaError),
    /// The anchor counts no rule of this family. See the module docs: this is
    /// deliberately not a reading of zero.
    #[error(
        "the anchor has no interface-scoped {family:?} deny to count ({label:?}); a window with \
         no such rule counts nothing, which is indistinguishable from a guest that sent nothing"
    )]
    NoSuchDeny {
        family: DeniedFamily,
        label: &'static str,
    },
    /// The reading is not what the profile requires.
    #[error("the {family:?} denies counted {observed:?} across the window, expected {expected:?}")]
    Unmet {
        family: DeniedFamily,
        expected: DenyExpectation,
        observed: DenyReading,
    },
}

/// Grade one window: what the family's denies counted, and whether that is
/// what was expected.
pub fn grade_deny_window(
    before: &PfCounterSnapshot,
    after: &PfCounterSnapshot,
    family: DeniedFamily,
    expected: DenyExpectation,
) -> Result<DenyReading, DenyRefusal> {
    let delta = before.delta(after)?;
    let label = family.label();
    let mut observed = DenyReading {
        packets: 0,
        rules: 0,
    };
    for (key, counters) in delta.iter() {
        // Both halves of the key, because either alone admits a rule this
        // window is not about. The label alone would count a rule scoped to
        // no interface — which the wire format allows even though the helper
        // never files one that way — and a document carrying only that would
        // then satisfy `Unmoved` with no interface deny in it at all.
        if key.label() != label || key.interface().is_none() {
            continue;
        }
        observed.packets = observed.packets.saturating_add(counters.packets);
        observed.rules += 1;
    }
    if observed.rules == 0 {
        return Err(DenyRefusal::NoSuchDeny { family, label });
    }
    let met = match expected {
        DenyExpectation::RoseByAtLeast(least) => observed.packets >= least,
        DenyExpectation::Unmoved => observed.packets == 0,
    };
    if met {
        Ok(observed)
    } else {
        Err(DenyRefusal::Unmet {
            family,
            expected,
            observed,
        })
    }
}

#[cfg(test)]
mod tests;
