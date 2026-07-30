//! Deciding whether a daemon-owned notes repo has accumulated enough loose
//! objects to be worth packing.
//!
//! Pure: this module measures nothing and runs nothing. It parses the output of
//! `git count-objects -v` into a count, and turns that count plus a threshold
//! into an inert `CompactionDecision` that [`super::NotesRepo`] interprets.
//! (That type and its `decide` constructor are crate-private, so they are named
//! here rather than linked: nothing outside writ interprets a decision.)
//! Keeping the policy here — rather than passing `--auto` and letting git decide
//! — is what makes it inspectable and property-testable, and it is why the
//! threshold is a value in this codebase rather than a config key git reads.
//!
//! ## Why writ decides this at all
//!
//! Git used to. Every `git commit` and `git fetch` spawned
//! `git maintenance run --auto --detach`, which packed loose objects in the
//! background. Writ suppresses that (see [`writ_core::git_env`]) because a
//! detached writer in a repo writd owns is a second writer it never spawned,
//! cannot wait for, and whose lifetime no writd operation bounds. Suppressing it
//! left the repo growing loose objects forever, so the compaction it used to get
//! for free is now writ's job to schedule deliberately.
//!
//! ## What the threshold is
//!
//! [`CompactionThreshold::GIT_DEFAULT`] is git's own `gc.auto` default. The
//! intent is to do what git would have done, at the point git would have done
//! it, but synchronously and under the lock writ already holds for every other
//! mutation of the repo.
//!
//! One deliberate difference: git's `--auto` does not count loose objects, it
//! estimates them by counting one fanout directory (`objects/17/`) and
//! multiplying by 256. `count-objects -v`'s `count:` is the true total, so this
//! fires on the real figure rather than a sample. That makes it more accurate,
//! not more eager: for a repo with evenly-distributed OIDs the two agree.

/// The number of loose (unpacked) objects in a repo's object database.
///
/// A newtype because "6700" and "3" are not interchangeable integers here: one
/// is a policy threshold and the other is a measurement, and mixing them up
/// silently inverts the comparison. Ordered so `decide` can compare a
/// measurement against a threshold without unwrapping either.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct LooseObjectCount(u64);

impl LooseObjectCount {
    /// Wrap a raw count.
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// The raw count, for formatting into an operator log line.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for LooseObjectCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How many loose objects a repo may hold before compaction is worthwhile.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompactionThreshold(LooseObjectCount);

impl CompactionThreshold {
    /// Git's own `gc.auto` default: 6700 loose objects.
    ///
    /// Not a number writ invented. Git applies it to every repo that has not
    /// disabled auto-maintenance, so it is the figure this repo would have been
    /// compacted at before writ suppressed git's background writer. Choosing our
    /// own number would mean claiming to know better than upstream about a
    /// tradeoff (loose-object lookup cost vs. repack cost) that upstream has
    /// tuned against far more repositories than writ will ever see.
    pub const GIT_DEFAULT: Self = Self(LooseObjectCount::new(6700));

    /// A threshold at an arbitrary count. Tests use small values so a
    /// compaction can be provoked with a handful of notes instead of thousands.
    pub const fn new(loose_objects: LooseObjectCount) -> Self {
        Self(loose_objects)
    }
}

/// What to do about a repo's current loose-object count: inert data, so the
/// policy can be property-tested without spawning git, and so the shell that
/// interprets it has one `match` rather than a condition spread across it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompactionDecision {
    /// Below the threshold. Leave the repo alone.
    Skip { loose_objects: LooseObjectCount },
    /// At or above the threshold. Pack the loose objects.
    Compact { loose_objects: LooseObjectCount },
}

/// Decide whether a repo holding `loose_objects` objects should be compacted.
///
/// At-or-above rather than strictly-above, so a threshold of zero means "always
/// compact" — which is what a test wants, and what a reader would assume.
///
/// Deliberately knows nothing about the retry backoff. The shell consults that
/// *before* measuring, because the measurement is itself a git invocation that
/// can be the thing failing, so a gate applied to this decision would arrive too
/// late to bound anything.
pub(crate) const fn decide(
    loose_objects: LooseObjectCount,
    threshold: CompactionThreshold,
) -> CompactionDecision {
    if loose_objects.get() >= threshold.0.get() {
        CompactionDecision::Compact { loose_objects }
    } else {
        CompactionDecision::Skip { loose_objects }
    }
}

/// Did a completed `gc` actually reduce the loose-object count?
///
/// Compaction that succeeds without achieving anything is worse than one that
/// fails, because a failure closes the retry gate and this does not: the count is
/// still over the threshold, so the next request runs another full `gc`, forever.
///
/// That is reachable. Measured on git 2.54: with `gc.cruftPacks=false` in
/// `<repo>/config`, a `gc` leaves young unreachable objects loose and the count
/// is unchanged across the call. [`super::GC_ARGV`] imposes `--cruft` to remove
/// that particular cause, but "the repack ran and the count did not move" is
/// worth detecting on its own, because the flag only covers the cause we know
/// about.
///
/// A repo that had nothing loose to begin with is never ineffective — there was
/// no progress available to make, so the absence of progress says nothing.
pub(crate) const fn made_progress(before: LooseObjectCount, after: LooseObjectCount) -> bool {
    before.get() == 0 || after.get() < before.get()
}

/// Read the loose-object count out of `git count-objects -v` output.
///
/// The format is one `key: value` per line. We interpret exactly one key —
/// `count` — and ignore every other line, because the set of keys grows between
/// git versions and one of them (`alternate: <path>`) carries a value that is
/// not a number at all. Ignoring unknown keys is therefore not laziness: a
/// parser that insisted every value be numeric would fail on any repo with an
/// alternate object store configured.
///
/// A missing, duplicated, or non-numeric `count` is an error rather than a
/// default. Defaulting to zero would read as "nothing to compact" and silently
/// disable compaction forever the moment git's output shape changed.
pub fn parse_count_objects_verbose(
    stdout: &str,
) -> Result<LooseObjectCount, CountObjectsParseError> {
    let mut found: Option<LooseObjectCount> = None;
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "count" {
            continue;
        }
        // Structural error first: two `count:` lines mean the output is not the
        // shape we think it is, which is worth saying even if the second value
        // also happens to be unparseable.
        if found.is_some() {
            return Err(CountObjectsParseError::DuplicateCount);
        }
        let raw = value.trim();
        let parsed = raw
            .parse::<u64>()
            .map_err(|_| CountObjectsParseError::UnparseableCount {
                raw: raw.to_string(),
            })?;
        found = Some(LooseObjectCount::new(parsed));
    }
    found.ok_or(CountObjectsParseError::MissingCount)
}

/// Why `git count-objects -v` output could not be read.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CountObjectsParseError {
    #[error("git count-objects -v output has no `count:` line")]
    MissingCount,
    #[error("git count-objects -v output has more than one `count:` line")]
    DuplicateCount,
    #[error("git count-objects -v reported a non-numeric loose-object count {raw:?}")]
    UnparseableCount { raw: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The shape git 2.54 actually emits for a bare repo, used as the base for
    /// tests that vary one thing about it.
    fn real_output(count: u64) -> String {
        format!(
            "count: {count}\nsize: 12\nin-pack: 2\npacks: 1\nsize-pack: 1\nprune-packable: 0\ngarbage: 0\nsize-garbage: 0\n"
        )
    }

    #[test]
    fn parses_the_output_git_actually_emits() {
        assert_eq!(
            parse_count_objects_verbose(&real_output(3)).unwrap(),
            LooseObjectCount::new(3)
        );
    }

    #[test]
    fn tolerates_an_alternate_line_whose_value_is_not_a_number() {
        // `count-objects -v` prints one `alternate:` line per configured
        // alternate object store. A parser that required numeric values would
        // reject every repo that has one.
        let out = format!("{}alternate: /srv/shared/objects\n", real_output(7));
        assert_eq!(
            parse_count_objects_verbose(&out).unwrap(),
            LooseObjectCount::new(7)
        );
    }

    #[test]
    fn tolerates_unknown_keys_blank_lines_and_reordering() {
        let out = "\nsize-garbage: 0\nfuture-key: whatever\n\ncount: 42\npacks: 9\n";
        assert_eq!(
            parse_count_objects_verbose(out).unwrap(),
            LooseObjectCount::new(42)
        );
    }

    #[test]
    fn is_not_confused_by_keys_that_merely_contain_count() {
        // `prune-packable` and `size-pack` are real keys; a substring match on
        // "count" would be fine today, but a future `loose-count:` would not be.
        let out = "loose-count: 999\nrecount: 888\ncount: 5\n";
        assert_eq!(
            parse_count_objects_verbose(out).unwrap(),
            LooseObjectCount::new(5)
        );
    }

    #[test]
    fn rejects_output_with_no_count_line() {
        let out = "size: 12\npacks: 1\n";
        assert_eq!(
            parse_count_objects_verbose(out).unwrap_err(),
            CountObjectsParseError::MissingCount
        );
    }

    #[test]
    fn rejects_a_non_numeric_count() {
        let err = parse_count_objects_verbose("count: banana\n").unwrap_err();
        assert_eq!(
            err,
            CountObjectsParseError::UnparseableCount {
                raw: "banana".to_string()
            }
        );
    }

    #[test]
    fn rejects_a_negative_count() {
        // Not a thing git emits, but `-1` parsed as a `u64` failure rather than
        // wrapping to `u64::MAX` is the difference between "refuse" and
        // "compact immediately, forever".
        let err = parse_count_objects_verbose("count: -1\n").unwrap_err();
        assert_eq!(
            err,
            CountObjectsParseError::UnparseableCount {
                raw: "-1".to_string()
            }
        );
    }

    #[test]
    fn rejects_duplicated_count_lines() {
        assert_eq!(
            parse_count_objects_verbose("count: 1\ncount: 2\n").unwrap_err(),
            CountObjectsParseError::DuplicateCount
        );
    }

    proptest! {
        /// Round trip: any count git could report is recovered exactly.
        #[test]
        fn any_count_round_trips_through_the_real_output_shape(count: u64) {
            prop_assert_eq!(
                parse_count_objects_verbose(&real_output(count)).unwrap(),
                LooseObjectCount::new(count)
            );
        }

        /// The whole of the policy, stated independently of how `decide` is
        /// written: compact exactly when the measurement reaches the threshold.
        ///
        /// Over the *whole* domain. This does not on its own pin the boundary —
        /// see the two properties below for why.
        #[test]
        fn decide_compacts_exactly_when_the_count_reaches_the_threshold(
            count: u64,
            threshold: u64,
        ) {
            let loose = LooseObjectCount::new(count);
            let decision = decide(loose, CompactionThreshold::new(LooseObjectCount::new(threshold)));
            let compacted = matches!(decision, CompactionDecision::Compact { .. });
            prop_assert_eq!(compacted, count >= threshold);
        }

        /// The same statement over a small domain, so `count == threshold`
        /// actually occurs.
        ///
        /// The wide-domain version above looks like it covers this and does not:
        /// two independent uniform `u64`s collide with probability about
        /// 2^-64, so it never once evaluates the case that distinguishes `>=`
        /// from `>`. Mutation testing is what surfaced that — the wide property
        /// passed happily against a `decide` built on `>`.
        #[test]
        fn decide_agrees_with_the_policy_on_a_domain_dense_enough_to_hit_equality(
            count in 0u64..32,
            threshold in 0u64..32,
        ) {
            let loose = LooseObjectCount::new(count);
            let decision = decide(loose, CompactionThreshold::new(LooseObjectCount::new(threshold)));
            let compacted = matches!(decision, CompactionDecision::Compact { .. });
            prop_assert_eq!(compacted, count >= threshold);
        }

        /// The boundary, pinned directly for every threshold: at the threshold
        /// compact, one below skip. This is the sharpest form of the
        /// "at-or-above, not strictly-above" claim in `decide`'s docstring, and
        /// the assertion that kills a `>` regression outright.
        #[test]
        fn decide_compacts_at_the_threshold_and_skips_one_below(threshold: u64) {
            let t = CompactionThreshold::new(LooseObjectCount::new(threshold));

            let at_threshold = decide(LooseObjectCount::new(threshold), t);
            let compacts_at = matches!(at_threshold, CompactionDecision::Compact { .. });
            prop_assert!(compacts_at, "a count equal to the threshold must compact");

            if let Some(below) = threshold.checked_sub(1) {
                let just_below = decide(LooseObjectCount::new(below), t);
                let skips_below = matches!(just_below, CompactionDecision::Skip { .. });
                prop_assert!(skips_below, "one object below the threshold must skip");
            }
        }

        /// Whichever branch fires carries the measurement through unchanged, so
        /// the shell can log what it saw without measuring a second time.
        #[test]
        fn decide_carries_the_observed_count_into_either_branch(count: u64, threshold: u64) {
            let loose = LooseObjectCount::new(count);
            let decision = decide(loose, CompactionThreshold::new(LooseObjectCount::new(threshold)));
            let carried = match decision {
                CompactionDecision::Skip { loose_objects }
                | CompactionDecision::Compact { loose_objects } => loose_objects,
            };
            prop_assert_eq!(carried, loose);
        }

        /// A threshold of zero always compacts. This is what the behavioural
        /// tests rely on to provoke a real `git gc` from a handful of notes.
        ///
        /// `Just(0)` is in the strategy on purpose: a bare `any::<u64>()` never
        /// generates the empty repo, which is the one case where "always" is
        /// doing any work.
        #[test]
        fn a_zero_threshold_always_compacts(
            count in prop_oneof![Just(0u64), 1u64..1_000, any::<u64>()],
        ) {
            let decision = decide(
                LooseObjectCount::new(count),
                CompactionThreshold::new(LooseObjectCount::new(0)),
            );
            let compacted = matches!(decision, CompactionDecision::Compact { .. });
            prop_assert!(compacted, "a zero threshold must always compact");
        }

        /// A `gc` that reduces the count made progress; one that does not, did
        /// not. Stated over a dense domain so `after == before` — the case the
        /// whole check exists for — actually occurs.
        #[test]
        fn progress_is_exactly_a_strict_decrease_in_a_non_empty_repo(
            before in 1u64..32,
            after in 0u64..32,
        ) {
            let progressed = made_progress(
                LooseObjectCount::new(before),
                LooseObjectCount::new(after),
            );
            prop_assert_eq!(progressed, after < before);
        }

        /// An empty repo never counts as having failed to progress, whatever the
        /// call reports afterwards. There was no progress available to make, so
        /// its absence is not evidence of an ineffective `gc`.
        #[test]
        fn an_empty_repo_always_counts_as_progress(after: u64) {
            let progressed = made_progress(
                LooseObjectCount::new(0),
                LooseObjectCount::new(after),
            );
            prop_assert!(progressed, "a repo with nothing loose cannot have stalled");
        }
    }

    /// The exact shape of the loop being detected: a `gc` ran, and the count did
    /// not move. Pinned separately from the property because it is the scenario
    /// measured on git 2.54 with `gc.cruftPacks=false`.
    #[test]
    fn an_unchanged_count_across_a_gc_is_not_progress() {
        let stuck = LooseObjectCount::new(6_700);
        assert!(
            !made_progress(stuck, stuck),
            "a gc that left the count exactly where it was achieved nothing"
        );
    }

    #[test]
    fn the_production_threshold_is_gits_own_default() {
        // Pinned rather than derived: if someone changes this, it should be a
        // deliberate edit to a test that says why the number is 6700.
        assert_eq!(
            CompactionThreshold::GIT_DEFAULT,
            CompactionThreshold::new(LooseObjectCount::new(6700))
        );
    }
}
