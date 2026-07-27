//! One spelling for a quantity of bytes.
//!
//! The broker is largely a machine for enforcing size limits: bundle caps,
//! proxy request and response caps, NAR and narinfo caps, push body caps,
//! cache eviction ceilings. Before this type they were spelled two ways —
//! eight of the eleven configured caps as `u64`, the three git-push ones as
//! `usize` — for one concept, with the conversions written out at whichever
//! site happened to need them.
//!
//! No truncation bug had resulted: every conversion in the tree was either a
//! widening `len() as u64` (lossless) or a checked `usize::try_from`. The cost
//! was that nothing *stopped* the next one being neither, and a reader could
//! not tell from a signature which spelling a given limit used.
//!
//! So the point of this type is not that it fixes an outstanding defect. It is
//! that the narrowing conversion — the only one that can lose information — now
//! exists in exactly one place ([`ByteSize::to_usize`]), returns an `Option`,
//! and cannot be written any other way.
//!
//! Represented as `u64` because that is what a size limit means independently
//! of the host's pointer width: a cap on a 64 MiB bundle is 64 MiB whether or
//! not the machine could address it. Going the other way — measuring something
//! already in memory — is [`ByteSize::of`], which is infallible because a
//! `usize` always fits a `u64` on every platform this builds for.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A quantity of bytes: a limit, a measurement, or a budget.
///
/// Serialises transparently as a JSON number, so configuration files that
/// predate this type parse unchanged.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    pub const ZERO: Self = Self(0);

    /// A count of bytes.
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Kibibytes, mebibytes, gibibytes. Named constructors because the tree
    /// previously spelled the same quantity `256 << 20` in one place and
    /// `512 * 1024 * 1024` in another, and neither reads as its magnitude.
    pub const fn kib(count: u64) -> Self {
        Self(count * 1024)
    }

    pub const fn mib(count: u64) -> Self {
        Self(count * 1024 * 1024)
    }

    pub const fn gib(count: u64) -> Self {
        Self(count * 1024 * 1024 * 1024)
    }

    /// Measure something already in memory. Infallible: `usize` fits in `u64`
    /// on every supported platform.
    pub const fn of(len: usize) -> Self {
        Self(len as u64)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The one narrowing conversion, for the sites that must compare against a
    /// `usize` length or pre-size an allocation.
    ///
    /// `None` when the limit exceeds what this platform can address — a
    /// configured cap larger than `usize::MAX` is not a limit this process can
    /// enforce by buffering, and silently clamping it would enforce something
    /// the operator did not ask for.
    pub fn to_usize(self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }

    /// Saturating addition, for headroom arithmetic over a configured cap.
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

impl fmt::Display for ByteSize {
    /// The bare count. Deliberately not a human-readable rendering: these
    /// values appear in error messages an operator matches against a config
    /// file, and `67108864` is what they wrote there.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Measuring never loses information, and round-trips back to the same
        /// length whenever the platform can express it.
        #[test]
        fn measuring_a_length_round_trips(len: usize) {
            let size = ByteSize::of(len);
            prop_assert_eq!(size.get(), len as u64);
            prop_assert_eq!(size.to_usize(), Some(len));
        }

        /// The narrowing conversion refuses rather than truncates. On a 64-bit
        /// platform nothing exceeds `usize::MAX`, so this asserts the
        /// equivalence that actually holds: convertible exactly when it fits.
        #[test]
        fn narrowing_is_exact_or_refused(bytes: u64) {
            let size = ByteSize::from_bytes(bytes);
            match size.to_usize() {
                Some(narrowed) => prop_assert_eq!(narrowed as u64, bytes),
                None => prop_assert!(bytes > usize::MAX as u64),
            }
        }

        /// Ordering on the wrapper is ordering on the count, so comparisons
        /// against a limit keep their meaning.
        #[test]
        fn ordering_follows_the_count(a: u64, b: u64) {
            prop_assert_eq!(
                ByteSize::from_bytes(a).cmp(&ByteSize::from_bytes(b)),
                a.cmp(&b)
            );
        }

        /// The wire form is the bare number, so configs written before this
        /// type parse unchanged.
        #[test]
        fn serialises_as_a_bare_number(bytes: u64) {
            let json = serde_json::to_string(&ByteSize::from_bytes(bytes)).unwrap();
            prop_assert_eq!(&json, &bytes.to_string());
            let parsed: ByteSize = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed.get(), bytes);
        }

        /// Headroom arithmetic cannot wrap a cap around to a tiny one.
        #[test]
        fn saturating_add_never_wraps(a: u64, b: u64) {
            let sum = ByteSize::from_bytes(a).saturating_add(ByteSize::from_bytes(b));
            prop_assert!(sum.get() >= a.max(b));
        }
    }

    #[test]
    fn scale_constructors_agree_with_their_magnitudes() {
        assert_eq!(ByteSize::kib(1).get(), 1024);
        assert_eq!(ByteSize::mib(64).get(), 64 * 1024 * 1024);
        assert_eq!(ByteSize::gib(2).get(), 2 * 1024 * 1024 * 1024);
        // The two spellings the tree used to mix, now provably the same value.
        assert_eq!(ByteSize::mib(256).get(), 256 << 20);
        assert_eq!(ByteSize::mib(512).get(), 512 * 1024 * 1024);
    }

    #[test]
    fn display_is_the_bare_count() {
        assert_eq!(ByteSize::mib(64).to_string(), "67108864");
    }
}
