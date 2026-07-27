//! Accumulating validation: check every independent thing, then report all
//! the failures at once.
//!
//! Config validation is the operator's compiler. A compiler that stopped at
//! the first type error would be miserable to use, and a daemon that refuses
//! to start over one bad field — while silently holding six more — costs a
//! restart per mistake. These types let a validator run every independent
//! check and hand back the whole list.
//!
//! The primitives are:
//!
//! - [`Errors`], a **non-empty** list of failures. "Rejected, but here are no
//!   reasons" is not representable.
//! - [`Accumulator`], which records `Result`s without short-circuiting.
//! - [`Failed`], a witness that at least one failure was recorded. It is what
//!   makes [`Errors`]'s non-emptiness a compile-time property rather than a
//!   convention: the only way to obtain an [`Errors`] from an accumulator is
//!   to surrender a `Failed`, and the only way to mint a `Failed` is for
//!   [`Accumulator::record`] to have pushed an error.
//!
//! The intended shape at a call site is: record each independent check, then
//! [`Accumulator::unpack`] the recorded values in one go.
//!
//! ```ignore
//! let mut errors = Accumulator::new();
//! let port = errors.record(Port::new(raw_port));
//! let host = errors.record(Host::parse(&raw_host));
//! // Both checks have run; a bad port no longer hides a bad host.
//! let (port, host) = errors.unpack(all_recorded!(port, host))?;
//! ```

use std::fmt;

/// Proof that at least one failure has been recorded.
///
/// Zero-sized and deliberately unconstructable outside this module:
/// [`Accumulator::record`] mints one only on the path where it pushes an
/// error. [`Accumulator::into_errors`] demands one, which is what makes an
/// empty [`Errors`] unrepresentable.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Failed(());

/// A non-empty list of validation failures, in the order they were found.
///
/// Non-empty by construction — see [`Failed`]. Consumers can therefore
/// render a report without a "no errors" branch that should never happen.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Errors<E> {
    first: E,
    rest: Vec<E>,
}

impl<E> Errors<E> {
    /// A report of exactly one failure. The single-error escape hatch for
    /// validators that genuinely have nothing to accumulate.
    pub fn single(error: E) -> Self {
        Self {
            first: error,
            rest: Vec::new(),
        }
    }

    /// The first failure found. Useful when a caller wants to act on one
    /// error rather than render the whole report.
    pub fn first(&self) -> &E {
        &self.first
    }

    /// How many failures this report carries. Always at least 1.
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Always `false`; present because clippy asks for it next to [`Self::len`],
    /// and because saying so in the type's own API documents the invariant.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Every failure, in discovery order.
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }

    /// Every failure, in discovery order, by value.
    pub fn into_vec(self) -> Vec<E> {
        let mut all = Vec::with_capacity(self.len());
        all.push(self.first);
        all.extend(self.rest);
        all
    }
}

impl<E> IntoIterator for Errors<E> {
    type Item = E;
    type IntoIter = std::vec::IntoIter<E>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<E: fmt::Display> fmt::Display for Errors<E> {
    /// One failure renders as itself, so the common case reads exactly as it
    /// did before accumulation existed. Several render as a counted, bulleted
    /// list — the operator's to-do list for the next edit.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rest.is_empty() {
            return write!(f, "{}", self.first);
        }
        write!(f, "{} problems found:", self.len())?;
        for error in self.iter() {
            write!(f, "\n  - {error}")?;
        }
        Ok(())
    }
}

impl<E: std::error::Error> std::error::Error for Errors<E> {
    /// Deliberately no `source`: a report of several failures has several
    /// sources, and picking one would hide the rest from anything that walks
    /// the chain. [`fmt::Display`] carries them all.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Collects failures from independent checks without short-circuiting.
///
/// See the [module docs](self) for the intended call shape.
#[derive(Debug)]
pub struct Accumulator<E> {
    errors: Vec<E>,
}

impl<E> Default for Accumulator<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Accumulator<E> {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Record one check. On success the value passes through; on failure the
    /// error is stored and the caller gets a [`Failed`] witness instead.
    ///
    /// The returned `Result` is deliberately not the input `Result`: it
    /// carries no error payload, because the payload now lives in the
    /// accumulator. Callers thread the witness to [`Self::unpack`].
    pub fn record<T>(&mut self, result: Result<T, E>) -> Result<T, Failed> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.errors.push(error);
                Err(Failed(()))
            }
        }
    }

    /// [`Self::record`] for a check whose error type converts into this
    /// accumulator's.
    pub fn record_from<T, E2: Into<E>>(&mut self, result: Result<T, E2>) -> Result<T, Failed> {
        self.record(result.map_err(Into::into))
    }

    /// Record a nested validator's whole report, flattening its failures into
    /// this one. Without this, an inner accumulation would collapse back to a
    /// single error at every level and the tiering would reappear.
    pub fn record_many<T, E2: Into<E>>(
        &mut self,
        result: Result<T, Errors<E2>>,
    ) -> Result<T, Failed> {
        match result {
            Ok(value) => Ok(value),
            Err(errors) => {
                self.errors.extend(errors.into_iter().map(Into::into));
                Err(Failed(()))
            }
        }
    }

    /// Give up now if anything has already failed; otherwise carry on with the
    /// same accumulator.
    ///
    /// This is the one legitimate reason to stop early, and it is about side
    /// effects rather than about errors: a group of checks that *creates*
    /// things should not run on behalf of a config that is already going to be
    /// rejected. Everything before the checkpoint still accumulates, so a
    /// checkpoint costs the operator at most one extra round-trip, and only
    /// when their config was wrong on two quite different axes.
    pub fn checkpoint(self) -> Result<Self, Errors<E>> {
        let mut errors = self.errors.into_iter();
        match errors.next() {
            None => Ok(Self { errors: Vec::new() }),
            Some(first) => Err(Errors {
                first,
                rest: errors.collect(),
            }),
        }
    }

    /// Surrender the witness for the accumulated report.
    ///
    /// Taking `Failed` by value is the whole trick: it can only have come
    /// from a [`Self::record`] call that pushed an error, so `self.errors` is
    /// non-empty and the `expect` below is discharged by the type system
    /// rather than by discipline.
    pub fn into_errors(self, _witness: Failed) -> Errors<E> {
        let mut errors = self.errors.into_iter();
        let first = errors
            .next()
            .expect("a Failed witness is minted only when an error is pushed");
        Errors {
            first,
            rest: errors.collect(),
        }
    }

    /// `Ok(())` when nothing failed, otherwise the whole report.
    pub fn finish(self) -> Result<(), Errors<E>> {
        let mut errors = self.errors.into_iter();
        match errors.next() {
            None => Ok(()),
            Some(first) => Err(Errors {
                first,
                rest: errors.collect(),
            }),
        }
    }

    /// Terminal operation: hand back `values` if every check passed, else the
    /// full report.
    ///
    /// `values` is normally built by [`all_recorded!`], which turns the
    /// individual `Result<_, Failed>` bindings into one tuple. The
    /// [`Self::finish`] call on the success path catches checks that were
    /// recorded but left out of the tuple, so a forgotten binding cannot
    /// silently drop a failure.
    pub fn unpack<T>(self, values: Result<T, Failed>) -> Result<T, Errors<E>> {
        match values {
            Ok(values) => self.finish().map(|()| values),
            Err(witness) => Err(self.into_errors(witness)),
        }
    }
}

/// Gather several [`Accumulator::record`] results into one tuple, short of the
/// first [`Failed`].
///
/// This is the destructuring half of the accumulate pattern: recording is
/// non-short-circuiting, but *using* the values requires all of them, and
/// this is where that requirement is discharged. Pair it with
/// [`Accumulator::unpack`].
/// Exported at the crate root by `macro_rules` convention; use it as
/// [`crate::config::accumulate::all_recorded`], which is where the re-export
/// below puts it. The binaries (`writd`) are separate crates, so `pub(crate)`
/// would not reach them.
#[macro_export]
macro_rules! all_recorded {
    ($($value:expr),+ $(,)?) => {
        // An immediately-invoked closure so `?` has a function boundary to
        // return through; it captures each binding by move, which is what
        // `?` on an owned `Result` needs anyway.
        (|| Ok::<_, $crate::config::accumulate::Failed>(($($value?,)+)))()
    };
}

pub use crate::all_recorded;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Recording a list of results and finishing reports exactly the failures
    /// in the list, in order — nothing dropped, nothing invented, nothing
    /// short-circuited.
    #[test]
    fn finish_reports_every_failure_in_order() {
        proptest!(|(results: Vec<Result<u8, String>>)| {
            let expected: Vec<String> = results
                .iter()
                .filter_map(|r| r.as_ref().err().cloned())
                .collect();
            let mut acc = Accumulator::new();
            for result in results {
                let _ = acc.record(result);
            }
            match acc.finish() {
                Ok(()) => prop_assert!(expected.is_empty()),
                Err(errors) => prop_assert_eq!(errors.into_vec(), expected),
            }
        });
    }

    /// The values a caller gets back are exactly the successes, and only when
    /// there were no failures at all.
    #[test]
    fn unpack_yields_values_only_when_nothing_failed() {
        proptest!(|(a: Result<u8, String>, b: Result<u16, String>, c: Result<u32, String>)| {
            let expected_errors: Vec<String> = [
                a.as_ref().err().cloned(),
                b.as_ref().err().cloned(),
                c.as_ref().err().cloned(),
            ]
            .into_iter()
            .flatten()
            .collect();
            let expected_values = match (a.clone(), b.clone(), c.clone()) {
                (Ok(a), Ok(b), Ok(c)) => Some((a, b, c)),
                _ => None,
            };

            let mut acc = Accumulator::new();
            let ra = acc.record(a);
            let rb = acc.record(b);
            let rc = acc.record(c);
            match acc.unpack(all_recorded!(ra, rb, rc)) {
                Ok(values) => prop_assert_eq!(Some(values), expected_values),
                Err(errors) => {
                    prop_assert_eq!(expected_values, None);
                    prop_assert_eq!(errors.into_vec(), expected_errors);
                }
            }
        });
    }

    /// A report is never empty, whatever it was built from.
    #[test]
    fn reports_are_always_non_empty() {
        proptest!(|(results: Vec<Result<u8, String>>)| {
            let mut acc = Accumulator::new();
            for result in results {
                let _ = acc.record(result);
            }
            if let Err(errors) = acc.finish() {
                prop_assert!(!errors.is_empty());
                let reported_len = errors.len();
                prop_assert_eq!(reported_len, errors.iter().count());
                // The self-reported length must be honest about the payload,
                // which is what "non-empty" actually has to mean.
                prop_assert!(!errors.into_vec().is_empty());
            }
        });
    }

    /// The rendered report mentions every failure — the property an operator
    /// actually depends on, since stderr is all they see.
    #[test]
    fn display_mentions_every_failure() {
        proptest!(|(first: String, rest: Vec<String>)| {
            let mut acc = Accumulator::new();
            let witness = acc.record::<()>(Err(first.clone())).unwrap_err();
            for error in &rest {
                let _ = acc.record::<()>(Err(error.clone()));
            }
            let errors = acc.into_errors(witness);
            let rendered = errors.to_string();
            for error in std::iter::once(&first).chain(rest.iter()) {
                prop_assert!(
                    rendered.contains(error.as_str()),
                    "rendered report {rendered:?} omits {error:?}"
                );
            }
        });
    }

    /// A lone failure renders as itself, so accumulation costs nothing in
    /// legibility for the overwhelmingly common one-mistake case.
    #[test]
    fn a_single_failure_renders_bare() {
        let errors = Errors::single("work root must be absolute");
        assert_eq!(errors.to_string(), "work root must be absolute");
        assert_eq!(errors.len(), 1);
    }

    /// Several failures render as a counted list.
    #[test]
    fn several_failures_render_as_a_list() {
        let mut acc = Accumulator::new();
        let witness = acc.record::<()>(Err("bad port")).unwrap_err();
        let _ = acc.record::<()>(Err("bad url"));
        assert_eq!(
            acc.into_errors(witness).to_string(),
            "2 problems found:\n  - bad port\n  - bad url"
        );
    }

    /// A nested report folds in whole, rather than collapsing to its first
    /// error — this is what stops tiering reappearing at each nesting level.
    #[test]
    fn nested_reports_flatten() {
        #[derive(Debug, Eq, PartialEq)]
        struct Outer(String);
        impl From<&'static str> for Outer {
            fn from(s: &'static str) -> Self {
                Outer(s.to_string())
            }
        }

        let mut inner = Accumulator::new();
        let witness = inner.record::<()>(Err("inner one")).unwrap_err();
        let _ = inner.record::<()>(Err("inner two"));
        let inner: Result<(), _> = Err(inner.into_errors(witness));

        let mut outer = Accumulator::<Outer>::new();
        let _ = outer.record_many(inner);
        let _ = outer.record_from::<(), &'static str>(Err("outer one"));

        assert_eq!(
            outer.finish().unwrap_err().into_vec(),
            vec![
                Outer("inner one".into()),
                Outer("inner two".into()),
                Outer("outer one".into())
            ]
        );
    }

    /// `unpack` still reports a failure that was recorded but omitted from the
    /// `all_recorded!` tuple, so a forgotten binding cannot swallow an error.
    #[test]
    fn unpack_catches_recorded_but_unlisted_failures() {
        let mut acc = Accumulator::new();
        let listed = acc.record(Ok::<u8, &str>(1));
        let _unlisted = acc.record::<u8>(Err("dropped on the floor"));
        let result = acc.unpack(all_recorded!(listed));
        assert_eq!(result.unwrap_err().into_vec(), vec!["dropped on the floor"]);
    }
}
