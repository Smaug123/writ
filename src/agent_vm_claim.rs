//! Taint tracking for everything a guest says.
//!
//! The agent VM is assumed compromised from the moment the agent command
//! starts, so every field of every probe record is a *claim* by a hostile
//! process rather than a fact. Three review rounds of an earlier IPv6-bypass
//! harness each found the same bug in a new place — the host reading a
//! guest-computed summary and treating it as evidence — so the distinction is
//! tracked in the types here rather than in the care of whoever edits the
//! grading code next. Its first consumer is the vertical proof's guest report
//! ([`crate::agent_vm_proof::guest`]).
//!
//! [`Claim`] has no accessor. A claim leaves this module by four doors, each
//! named for what it licenses:
//!
//! * [`Claim::corroborated_by`] compares the claim with a value the host holds
//!   itself. This is the only door that can *establish* anything, and it is
//!   available only for [`HostHeld`] types — a sealed set that deliberately
//!   excludes `bool`, so a guest-computed verdict has no upward path at all.
//! * The `doubt_*` combinators read a claim in order to *weaken* the host's own
//!   conclusion, yielding a [`Doubt`] that carries no value.
//! * [`Claim::interpreted_by`] hands a [`RawCapture`] to a host-authored
//!   parser. Parsing settles what bytes *say*, not whether they are true, so
//!   the result is itself a claim.
//! * [`Claim::guest_only_precondition`] reads a claim the host cannot check at
//!   all. It is loud on purpose, and carries an obligation described below.
//!
//! Every combinator that takes a function takes a `fn` pointer rather than a
//! closure, so none of them can capture the claimed value into the surrounding
//! scope. The escape hatch this module deliberately lacks is `into_inner`.
//!
//! # What is deliberately not closed
//!
//! `Claim` does not implement `PartialEq`. That is not an oversight: with it,
//! `claim == Claim::asserted(true)` recovers any guest verdict without going
//! near [`HostHeld`], and it is the reading a reasonable person writes without
//! noticing — an earlier version of this module shipped it, and the tests of
//! its first consumer used it.
//!
//! `Debug` and `Serialize` remain, and a determined author could round-trip a
//! value out through either. They are kept because the guest binary must
//! serialize its records and because diagnostics on a failed proof run matter,
//! and they are left as the moral equivalent of `unsafe`: possible, obvious in
//! review, and never the shape of an honest grading decision. The line drawn
//! here is between escapes someone might take by accident and escapes that
//! take deliberate laundering.

use serde::{Deserialize, Serialize};

/// A value reported by a process the host assumes to be compromised.
///
/// See the [module documentation](self) for how a claim becomes a fact.
///
/// The sanctioned route reaches a fact through a value the host holds:
///
/// ```
/// use writ::agent_vm_claim::{Claim, NonceHex};
///
/// // The host minted this nonce and never sent it to the guest, so bytes
/// // matching it can only have come from the listener that serves it.
/// let claimed = Claim::asserted(NonceHex::of(b"served-by-the-host-listener"));
/// assert!(claimed.corroborated_by(&NonceHex::of(b"served-by-the-host-listener")));
/// assert!(!claimed.corroborated_by(&NonceHex::of(b"some-other-listener")));
/// ```
///
/// Comparing claims directly does not compile, which is what stops a guest
/// verdict being read as evidence:
///
/// ```compile_fail
/// use writ::agent_vm_claim::Claim;
///
/// let claimed: Claim<bool> = Claim::asserted(true);
/// let _ = claimed == Claim::asserted(true);
/// ```
///
/// Nor does corroborating a boolean, because `bool` is not [`HostHeld`]:
///
/// ```compile_fail
/// use writ::agent_vm_claim::Claim;
///
/// let claimed: Claim<bool> = Claim::asserted(true);
/// let _ = claimed.corroborated_by(&true);
/// ```
///
/// Nor is a container the host holds no copy of — the escape that shipped
/// once, and that no reviewer spotted, was `Option<bool>` reaching [`HostHeld`]
/// through a seal it shared with another capability:
///
/// ```compile_fail
/// fn host_held<T: writ::agent_vm_claim::HostHeld>() {}
/// host_held::<Option<bool>>();
/// ```
///
/// That guard is written as a bound and not as an `impl` on purpose. An `impl`
/// in a doctest is rejected by the orphan rule whatever this module does, so it
/// stays green with the hole wide open — which is exactly what the first
/// version of this guard did. A bound fails for the reason claimed, and starts
/// compiling the moment any module in the crate opts `Option<bool>` in. The
/// positive control, so that the guard is known not to fail for everything:
///
/// ```
/// use writ::agent_vm_claim::{HostHeld, NonceHex};
///
/// fn host_held<T: HostHeld>() {}
/// host_held::<NonceHex>();
/// ```
///
/// Nor does letting a doubt choose the answer rather than withdraw it, because
/// `bool` names no withheld value for doubt to fall back to:
///
/// ```compile_fail
/// use writ::agent_vm_claim::Claim;
///
/// let claimed: Claim<bool> = Claim::asserted(true);
/// let _ = claimed.doubt_unless_true().shadowing(true);
/// ```
///
/// Nor does shadowing an `Option`, whose universal eliminator hands the second
/// conclusion straight back:  `shadowing(Some(true)).unwrap_or(false)` returns
/// the claimed boolean itself, one combinator after the doubt withdrew it.
///
/// ```compile_fail
/// use writ::agent_vm_claim::Claim;
///
/// let claimed: Claim<bool> = Claim::asserted(true);
/// let _ = claimed.doubt_unless_true().shadowing(Some(true));
/// ```
///
/// Nor does opting a local type into [`HostHeld`] to get around that, because
/// the trait is sealed:
///
/// ```compile_fail
/// #[derive(Eq, PartialEq)]
/// struct Verdict(bool);
/// impl writ::agent_vm_claim::HostHeld for Verdict {}
/// ```
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Claim<T>(T);

/// A type the host independently holds its own copy of.
///
/// Implemented only for values the host itself authored — the nonce it
/// generated, the address it chose, the plan text it wrote — because
/// corroboration is meaningless against anything else. It is deliberately
/// **not** implemented for `bool`, `usize`, or `String`: a guest's summary of
/// its own findings is not something the host can hold a copy of, so there is
/// no way to write the comparison that would treat one as evidence.
pub trait HostHeld: Eq + sealed::HostHeldSealed {}

/// Lowercase hex of a token the host minted.
///
/// This is the archetypal host-held value, and the reason it is a newtype
/// rather than a `String`: the host generates the nonce, keeps it, and never
/// sends it to the guest, so bytes matching it can only have been served by
/// the listener that holds it. Corroborating a `String` in general would say
/// nothing of the kind — provenance lives in the type, not the representation.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct NonceHex(String);

/// Maximum length of a nonce, in bytes, before hex encoding.
pub const MAX_NONCE_BYTES: usize = 128;

impl NonceHex {
    /// Encodes bytes as lowercase hex.
    ///
    /// # Panics
    ///
    /// If `bytes` exceeds [`MAX_NONCE_BYTES`]. The host mints its own nonces,
    /// so an oversized one is a programming error here rather than hostile
    /// input — and a value this constructor accepted but [`TryFrom`] would
    /// then refuse is a nonce that cannot survive its own round trip.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() <= MAX_NONCE_BYTES,
            "a host-minted nonce of {} bytes exceeds the {MAX_NONCE_BYTES}-byte bound",
            bytes.len()
        );
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        Self(encoded)
    }
}

impl TryFrom<String> for NonceHex {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        if value.len() > MAX_NONCE_BYTES * 2 {
            return Err(format!(
                "nonce hex of {} chars is out of bounds",
                value.len()
            ));
        }
        if !value.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err("nonce hex contains a non-hex character".to_string());
        }
        // Odd-length hex encodes no byte string, so it could never equal a
        // real nonce. Refusing it at the boundary keeps the type's contents
        // exactly the set of values `of` can produce.
        if !value.len().is_multiple_of(2) {
            return Err(format!(
                "nonce hex of {} chars is not whole bytes",
                value.len()
            ));
        }
        // Normalised at the boundary so that comparison is exact equality,
        // rather than a case-insensitive check a later caller might forget.
        Ok(Self(value.to_ascii_lowercase()))
    }
}

impl From<NonceHex> for String {
    fn from(value: NonceHex) -> Self {
        value.0
    }
}

impl HostHeld for NonceHex {}

/// Seals [`HostHeld`] so that its membership is a single auditable list rather
/// than something any module can opt into.
///
/// Without this, grading code could declare `struct Verdict(bool)`, implement
/// the marker, and corroborate a guest verdict against a value it invented —
/// recovering exactly what excluding `bool` was meant to prevent. Adding a type
/// here is therefore a deliberate edit to this module, and the reviewer sees
/// the whole set in one place.
///
/// The set holds purpose-specific newtypes, never broad primitives. A blanket
/// `impl HostHeld for u64` would hand `corroborated_by` to every claimed
/// number, including ones the host has no independent copy of — a guest's
/// measured elapsed time compared against an expected duration looks like
/// corroboration and is nothing of the sort. Representation is not provenance.
mod sealed {
    /// Implemented only for the types listed beneath it.
    ///
    /// This is deliberately *not* the same seal as [`WithheldSealed`]. Sharing
    /// one broke the guarantee outright: a blanket `Option<T>` implementation
    /// written for `Withheld` also admitted `impl HostHeld for Option<bool>`
    /// from any sibling module, and `corroborated_by(&Some(true))` then
    /// recovered a guest boolean without anyone editing this file. Two
    /// capabilities, two seals — and neither admits a foreign container.
    pub trait HostHeldSealed {}

    impl HostHeldSealed for super::NonceHex {}

    /// Seals [`super::Withheld`], whose membership is a different question:
    /// what may stand for "the host reached no conclusion".
    pub trait WithheldSealed {}

    // The vertical proof's verdict is host-only, as the grading is; the guest
    // binary that constructs claims never withdraws a conclusion.
    #[cfg(feature = "host")]
    impl WithheldSealed for crate::agent_vm_proof::guest::SessionVerdict {}

    #[cfg(test)]
    impl WithheldSealed for super::tests::Verdict {}
}

/// The result of reading a claim in order to doubt.
///
/// Carries no value, so nothing read for the purpose of doubting can be reused
/// for the purpose of concluding.
// `PartialEq` is available only to tests, for the same reason `Claim` has none
// at all: `doubts == Doubt::none()` reads the very bit this type exists to
// keep out of a conclusion, and reads it as *agreement*, which it never is.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[must_use = "a doubt that is not applied to an observation has been discarded"]
pub struct Doubt(bool);

/// A conclusion that can be withheld.
///
/// [`Doubt::shadowing`] takes only the conclusion the host reached for itself
/// and replaces it with `withheld()`. The caller does not get to name what
/// doubt produces, which is what stops `shadowing` being used to *select*
/// between two values a guest bit chooses between — the very upward path the
/// rest of this module removes.
///
/// Membership is sealed and deliberately excludes `Option<T>`, which was a
/// member once. `None` reads well as "no conclusion", but `Option` also carries
/// a universal eliminator taking a caller-chosen replacement, so
/// `shadowing(Some(true)).unwrap_or(false)` evaluates to the guest's own bit in
/// one idiomatic call: the second conclusion the signature refuses to accept,
/// supplied on the next line instead. A verdict whose withheld value is a
/// distinguished variant has no such eliminator — mapping it back to a
/// conclusion takes an explicit match, which is a thing a reviewer can see.
///
/// The one real member is the vertical proof's
/// [`SessionVerdict`](crate::agent_vm_proof::guest::SessionVerdict); the other
/// is the shape the tests use.
pub trait Withheld: sealed::WithheldSealed {
    /// The value that stands for "the host has no conclusion here".
    fn withheld() -> Self;
}

impl Doubt {
    /// The claim gave the host reason to distrust its own conclusion.
    pub const fn raised() -> Self {
        Self(true)
    }

    /// The claim gave no such reason. This is not the same as agreement.
    pub const fn none() -> Self {
        Self(false)
    }

    /// Combines two doubts: any doubt at all is doubt.
    pub fn or(self, other: Self) -> Self {
        Self(self.0 || other.0)
    }

    /// Combines any number of doubts.
    pub fn any(doubts: impl IntoIterator<Item = Self>) -> Self {
        doubts.into_iter().fold(Self::none(), Self::or)
    }

    /// Returns `host_derived`, or the withheld value if doubt was raised.
    ///
    /// This is the only elimination form, and it takes one conclusion rather
    /// than two on purpose. `host_derived` must be something the host reached
    /// from its own evidence; the point of a doubt is to withdraw such a
    /// conclusion, never to choose between a pair of them.
    pub fn shadowing<T: Withheld>(self, host_derived: T) -> T {
        if self.0 { T::withheld() } else { host_derived }
    }
}

impl<T> Claim<T> {
    /// Records what the guest said. Called on the guest side, and in tests.
    pub const fn asserted(value: T) -> Self {
        Self(value)
    }

    /// Reads a claim about the guest's own internals that nothing outside the
    /// guest can see, projecting it with a host-authored predicate.
    ///
    /// Every call site is a place where a compromised guest can manufacture
    /// the fact, so callers carry an obligation: confine these reads to
    /// *preconditions*, meaning facts whose falsity makes a case vacuous
    /// rather than safe. Then the worst a lie can achieve is a case that
    /// proves less than it claims to, never one that clears a boundary it
    /// never tested.
    ///
    /// That obligation is on the caller; nothing here enforces it. Prefer
    /// moving the question to something the host can observe for itself, and
    /// reach for this only when nothing outside the guest could ever see the
    /// answer.
    #[must_use]
    pub fn guest_only_precondition(&self, read: fn(&T) -> bool) -> bool {
        read(&self.0)
    }
}

impl<T: HostHeld> Claim<T> {
    /// Whether the claim agrees with a value the host holds itself.
    ///
    /// The host must supply its own copy, which is what makes this the only
    /// sound upward path: agreement is checked against the plan the host
    /// wrote, not against the guest's own account of it.
    pub fn corroborated_by(&self, held: &T) -> bool {
        self.0 == *held
    }
}

impl Claim<bool> {
    /// Doubt unless the guest claims this held.
    ///
    /// Used for the guest's account of what its own process did — that it
    /// attempted a step, that its platform supported one. A guest denying
    /// these can only make its case inconclusive.
    pub fn doubt_unless_true(&self) -> Doubt {
        if self.0 {
            Doubt::none()
        } else {
            Doubt::raised()
        }
    }

    /// Doubt if the guest claims this held.
    pub fn doubt_if_true(&self) -> Doubt {
        if self.0 {
            Doubt::raised()
        } else {
            Doubt::none()
        }
    }
}

impl<T> Claim<Option<T>> {
    /// Doubt if the guest reported something here — an error, a failure stage.
    pub fn doubt_if_present(&self) -> Doubt {
        if self.0.is_some() {
            Doubt::raised()
        } else {
            Doubt::none()
        }
    }
}

impl<T: Ord> Claim<T> {
    /// Doubt unless the claimed value reaches a floor the host computed.
    ///
    /// The floor must come from the host's own plan; comparing a claim with
    /// another claim would establish only that the guest was self-consistent.
    pub fn doubt_unless_at_least(&self, floor: &T) -> Doubt {
        if self.0 >= *floor {
            Doubt::none()
        } else {
            Doubt::raised()
        }
    }

    /// Doubt once the claimed value reaches a ceiling the host computed.
    pub fn doubt_if_at_least(&self, ceiling: &T) -> Doubt {
        if self.0 >= *ceiling {
            Doubt::raised()
        } else {
            Doubt::none()
        }
    }
}

/// Bytes the guest captured verbatim, with no interpretation applied.
///
/// A capture is how the guest reports something only it can see — the contents
/// of its own `/proc/net` tables — without also reporting what that content
/// means. The host's parser decides the meaning.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RawCapture(String);

impl RawCapture {
    /// Captures text, truncating at `limit` bytes on a character boundary.
    ///
    /// Truncation is not reported as a flag: the host sees the length it
    /// received and draws its own conclusion, so there is no claim to lie in.
    pub fn capture(text: &str, limit: usize) -> Self {
        let mut end = limit.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(text[..end].to_string())
    }
}

impl Claim<RawCapture> {
    /// Interprets a capture with a host-authored parser, keeping the taint.
    ///
    /// The parser is a `fn` pointer, so it cannot capture the text into the
    /// caller's scope: whatever the host learns from a capture, it learns
    /// through a parser it wrote and tested.
    ///
    /// The result is still a [`Claim`], and that is the whole point. Parsing
    /// settles what the bytes *say*; it cannot settle whether the guest showed
    /// the host its real tables. A guest that wants to report an empty
    /// `if_inet6` can simply send one, and the most rigorous parser in the
    /// world will agree that it is empty.
    pub fn interpreted_by<U>(&self, parse: fn(&str) -> U) -> Claim<U> {
        Claim(parse(&self.0.0))
    }

    /// How many bytes the guest sent, which the host checks against its own
    /// capture bound rather than trusting a truncation flag.
    pub fn captured_bytes(&self) -> usize {
        self.0.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn corroboration_needs_the_hosts_own_copy() {
        let claimed = Claim::asserted(NonceHex::of(b"abc"));
        assert!(claimed.corroborated_by(&NonceHex::of(b"abc")));
        assert!(!claimed.corroborated_by(&NonceHex::of(b"abd")));
    }

    /// The shape every real member of [`Withheld`] has: the withheld value is
    /// a variant of the verdict, not a hole a caller gets to fill.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Verdict {
        Observed,
        Indeterminate,
    }

    impl Withheld for Verdict {
        fn withheld() -> Self {
            Self::Indeterminate
        }
    }

    #[test]
    fn a_doubt_can_only_withdraw_a_conclusion() {
        assert_eq!(
            Doubt::none().shadowing(Verdict::Observed),
            Verdict::Observed
        );
        assert_eq!(
            Doubt::raised().shadowing(Verdict::Observed),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn a_capture_is_truncated_on_a_character_boundary() {
        // Four bytes, one character.
        let capture = RawCapture::capture("𝄞x", 3);
        assert_eq!(capture, RawCapture(String::new()));
        let capture = RawCapture::capture("𝄞x", 4);
        assert_eq!(capture, RawCapture("𝄞".to_string()));
    }

    proptest! {
        /// A nonce this module mints is always one it would accept back. The
        /// two constructors enforced different bounds once, so a host-minted
        /// value could serialize and then fail to deserialize.
        #[test]
        fn every_minted_nonce_survives_its_own_round_trip(
            bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_NONCE_BYTES),
        ) {
            let minted = NonceHex::of(&bytes);
            let text = String::from(minted.clone());
            let parsed = NonceHex::try_from(text);
            prop_assert!(parsed.is_ok(), "a minted nonce was refused: {:?}", parsed);
            prop_assert!(parsed.unwrap() == minted);
        }

        /// Doubt only ever accumulates: no combination of claims can talk the
        /// host back into a conclusion another claim withdrew.
        #[test]
        fn doubt_never_cancels(flags in proptest::collection::vec(any::<bool>(), 0..12)) {
            let doubts: Vec<Doubt> = flags
                .iter()
                .map(|raised| if *raised { Doubt::raised() } else { Doubt::none() })
                .collect();
            let combined = Doubt::any(doubts);
            let expected = if flags.iter().any(|raised| *raised) {
                Doubt::raised()
            } else {
                Doubt::none()
            };
            prop_assert_eq!(combined, expected);
        }

        /// A capture never grows and never splits a character, whatever bound
        /// it is given.
        #[test]
        fn a_capture_is_bounded_and_still_valid_text(
            text in ".{0,64}",
            limit in 0_usize..80,
        ) {
            let capture = RawCapture::capture(&text, limit);
            prop_assert!(capture.0.len() <= limit);
            prop_assert!(text.starts_with(&capture.0));
        }
    }
}
