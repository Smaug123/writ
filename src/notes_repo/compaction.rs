//! Deciding whether a daemon-owned notes repo has grown enough to be worth
//! repacking.
//!
//! Pure: this module measures nothing and runs nothing. It parses the output of
//! `git count-objects -v` into a pair of counts, and turns those counts plus a
//! threshold into an inert `CompactionDecision` that [`super::NotesRepo`]
//! interprets. (That type and its `decide` constructor are crate-private, so
//! they are named here rather than linked: nothing outside writ interprets a
//! decision.) Keeping the policy here — rather than passing `--auto` and letting
//! git decide — is what makes it inspectable and property-testable, and it is
//! why the thresholds are values in this codebase rather than config keys git
//! reads.
//!
//! ## Why writ decides this at all
//!
//! Git used to. Every `git commit` and `git fetch` spawned
//! `git maintenance run --auto --detach`, which packed loose objects in the
//! background. Writ suppresses that (see [`writ_core::git_env`]) because a
//! detached writer in a repo writd owns is a second writer it never spawned,
//! cannot wait for, and whose lifetime no writd operation bounds. Suppressing it
//! left the repo growing forever, so the compaction it used to get for free is
//! now writ's job to schedule deliberately.
//!
//! ## Two axes, because writ has two shapes of repo
//!
//! [`CompactionThreshold::GIT_DEFAULT`] is git's own pair: `gc.auto` = 6700
//! loose objects and `gc.autoPackLimit` = 50 packs. The intent is to do what git
//! would have done, at the point git would have done it, but synchronously and
//! under the lock writ already holds for every other mutation of the repo.
//!
//! Both axes are needed, and the second is not decoration. A daemon-owned notes
//! repo grows chiefly by **loose objects** — three per note write. Bailiff's
//! repo grows chiefly by whole **packs** — one per `fetch_from_remote` — so
//! under a loose-only policy it would have taken roughly 2200 note writes to
//! trip a threshold while accumulating a pack per fetch the whole time. On that
//! repo a loose-only threshold is not a smaller version of this policy; it is
//! one that essentially never fires.
//!
//! One deliberate difference from git remains: git's `--auto` does not count
//! loose objects, it estimates them by counting one fanout directory
//! (`objects/17/`) and multiplying by 256. `count-objects -v`'s `count:` is the
//! true total, so this fires on the real figure rather than a sample. That makes
//! it more accurate, not more eager: for a repo with evenly-distributed OIDs the
//! two agree. The pack count needs no such caveat — git reads it exactly too.

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

/// The number of packfiles in a repo's object database.
///
/// Its own newtype for the same reason as [`LooseObjectCount`], and the two are
/// deliberately not interchangeable: 50 packs and 50 loose objects are wildly
/// different states, and the thresholds that apply to them differ by two orders
/// of magnitude. A single integer type would let the two comparisons be swapped
/// with no complaint from the compiler.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct PackCount(u64);

impl PackCount {
    /// Wrap a raw count.
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// The raw count, for formatting into an operator log line.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for PackCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What one `git count-objects -v` reading says about a repo's size, along the
/// two axes git's own auto-maintenance watches.
///
/// One struct rather than two arguments everywhere, because the two are always
/// read from the same invocation and comparing a `before` from one reading with
/// an `after` from another would be meaningless.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ObjectCounts {
    pub loose_objects: LooseObjectCount,
    pub packs: PackCount,
}

impl std::fmt::Display for ObjectCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} loose, {} packs", self.loose_objects, self.packs)
    }
}

/// How large a repo may get before compaction is worthwhile, on each of the two
/// axes git's auto-maintenance watches.
///
/// Both are needed because the two answer different growth patterns, and writ
/// has repos of each shape. A daemon-owned notes repo grows chiefly by *loose
/// objects* — three per note write. Bailiff's repo grows chiefly by whole
/// *packs* — one per `fetch_from_remote` — and would have taken roughly 2200
/// note writes to trip a loose-object threshold while accumulating a pack per
/// fetch the whole time. A loose-only threshold is not a smaller version of this
/// policy; on that repo it is one that essentially never fires.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompactionThreshold {
    loose_objects: LooseObjectCount,
    packs: PackCount,
}

impl CompactionThreshold {
    /// Git's own defaults: `gc.auto` = 6700 loose objects, `gc.autoPackLimit`
    /// = 50 packs.
    ///
    /// Not numbers writ invented. Git applies them to every repo that has not
    /// disabled auto-maintenance, so they are the figures this repo would have
    /// been compacted at before writ suppressed git's background writer.
    /// Choosing our own would mean claiming to know better than upstream about a
    /// tradeoff (lookup cost vs. repack cost) that upstream has tuned against
    /// far more repositories than writ will ever see.
    pub const GIT_DEFAULT: Self = Self {
        loose_objects: LooseObjectCount::new(6700),
        packs: PackCount::new(50),
    };

    /// A threshold at arbitrary counts. Tests use small values so a compaction
    /// can be provoked with a handful of notes or fetches instead of thousands.
    pub const fn new(loose_objects: LooseObjectCount, packs: PackCount) -> Self {
        Self {
            loose_objects,
            packs,
        }
    }
}

/// Which axis (or axes) put a repo over the line.
///
/// Carried rather than discarded for two reasons, and the second is a
/// correctness one. An operator reading "compacted: 51 packs" is looking at a
/// different story from "compacted: 6700 loose objects" — the first is a repo
/// that fetches a lot, the second one that writes a lot. And the
/// effectiveness check has to know: a `gc` triggered by pack count has to be
/// judged on whether *packs* fell, because a repo with no loose objects at all
/// can trip the pack threshold, and judging it on loose objects would call every
/// such compaction effective whether or not it consolidated anything.
///
/// `pub` rather than crate-private, unlike `CompactionDecision`: this one
/// reaches the outside world on [`super::CompactionOutcome::Compacted`], because
/// bailiff logs the outcome too and "which axis fired" is as much a part of that
/// report as the counts. `CompactionDecision` stays private because nothing
/// outside writ interprets a *plan*.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompactionTrigger {
    LooseObjects,
    Packs,
    Both,
}

impl std::fmt::Display for CompactionTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LooseObjects => "loose objects",
            Self::Packs => "packs",
            Self::Both => "loose objects and packs",
        })
    }
}

/// What to do about a repo's current size: inert data, so the policy can be
/// property-tested without spawning git, and so the shell that interprets it has
/// one `match` rather than a condition spread across it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompactionDecision {
    /// Under both thresholds. Leave the repo alone.
    Skip { counts: ObjectCounts },
    /// At or above at least one threshold. Repack.
    Compact {
        counts: ObjectCounts,
        trigger: CompactionTrigger,
    },
}

/// Decide whether a repo of this size should be compacted.
///
/// At-or-above rather than strictly-above on each axis, so a threshold of zero
/// means "always compact" — which is what a test wants, and what a reader would
/// assume.
///
/// Deliberately knows nothing about the retry backoff. The shell consults that
/// *before* measuring, because the measurement is itself a git invocation that
/// can be the thing failing, so a gate applied to this decision would arrive too
/// late to bound anything.
pub(crate) const fn decide(
    counts: ObjectCounts,
    threshold: CompactionThreshold,
) -> CompactionDecision {
    let loose_over = counts.loose_objects.get() >= threshold.loose_objects.get();
    let packs_over = counts.packs.get() >= threshold.packs.get();
    match (loose_over, packs_over) {
        (false, false) => CompactionDecision::Skip { counts },
        (true, false) => CompactionDecision::Compact {
            counts,
            trigger: CompactionTrigger::LooseObjects,
        },
        (false, true) => CompactionDecision::Compact {
            counts,
            trigger: CompactionTrigger::Packs,
        },
        (true, true) => CompactionDecision::Compact {
            counts,
            trigger: CompactionTrigger::Both,
        },
    }
}

/// Did a completed `gc` actually shrink the repo along the axis that triggered
/// it?
///
/// Compaction that succeeds without achieving anything is worse than one that
/// fails, because a failure closes the retry gate and this does not: the repo is
/// still over the threshold, so the next request runs another full `gc`,
/// forever.
///
/// That is reachable. Measured on git 2.54: with `gc.cruftPacks=false` in
/// `<repo>/config`, a `gc` leaves young unreachable objects loose and the count
/// is unchanged across the call. [`super::GC_ARGV`] imposes `--cruft` to remove
/// that particular cause, but "the repack ran and the count did not move" is
/// worth detecting on its own, because the flag only covers the cause we know
/// about.
///
/// **Per axis, and that is the load-bearing part.** Judging a pack-triggered
/// compaction by its loose-object count would call it effective whenever the
/// repo had no loose objects — which is exactly the shape a fetch-heavy repo is
/// in when it trips the pack threshold, so the check would be blind precisely
/// where the new trigger fires. So each axis that was over its threshold must
/// have strictly decreased; an axis that was under it cannot have been the
/// trigger and is not asked to have moved.
///
/// An axis that was already at zero is never ineffective — there was no progress
/// available to make on it, so the absence of progress says nothing. (Reachable
/// only through a zero threshold, which is a test's way of saying "always
/// compact".)
pub(crate) const fn made_progress(
    before: ObjectCounts,
    after: ObjectCounts,
    threshold: CompactionThreshold,
) -> bool {
    let loose_ok = before.loose_objects.get() == 0
        || before.loose_objects.get() < threshold.loose_objects.get()
        || after.loose_objects.get() < before.loose_objects.get();
    let packs_ok = before.packs.get() == 0
        || before.packs.get() < threshold.packs.get()
        || after.packs.get() < before.packs.get();
    loose_ok && packs_ok
}

/// Read the loose-object and pack counts out of `git count-objects -v` output.
///
/// The format is one `key: value` per line. We interpret exactly two keys —
/// `count` and `packs` — and ignore every other line, because the set of keys
/// grows between git versions and one of them (`alternate: <path>`) carries a
/// value that is not a number at all. Ignoring unknown keys is therefore not
/// laziness: a parser that insisted every value be numeric would fail on any
/// repo with an alternate object store configured.
///
/// A missing, duplicated, or non-numeric value for either key is an error rather
/// than a default. Defaulting to zero would read as "nothing to compact" and
/// silently disable compaction forever the moment git's output shape changed.
///
/// Both keys are unconditionally present in the output — verified on git 2.54
/// for a fresh bare repo, a repo with only loose objects, and a packed repo:
/// `packs: 0` is emitted rather than the line being omitted. So requiring
/// `packs` costs nothing on a healthy git and is what makes a shape change loud
/// instead of silent.
pub fn parse_count_objects_verbose(stdout: &str) -> Result<ObjectCounts, CountObjectsParseError> {
    let mut loose_objects: Option<u64> = None;
    let mut packs: Option<u64> = None;
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let slot = match key {
            "count" => &mut loose_objects,
            "packs" => &mut packs,
            _ => continue,
        };
        // Structural error first: two lines for one key mean the output is not
        // the shape we think it is, which is worth saying even if the second
        // value also happens to be unparseable.
        if slot.is_some() {
            return Err(CountObjectsParseError::DuplicateKey {
                key: key.to_string(),
            });
        }
        let raw = value.trim();
        *slot = Some(
            raw.parse::<u64>()
                .map_err(|_| CountObjectsParseError::UnparseableValue {
                    key: key.to_string(),
                    raw: raw.to_string(),
                })?,
        );
    }
    Ok(ObjectCounts {
        loose_objects: LooseObjectCount::new(loose_objects.ok_or(
            CountObjectsParseError::MissingKey {
                key: "count".to_string(),
            },
        )?),
        packs: PackCount::new(packs.ok_or(CountObjectsParseError::MissingKey {
            key: "packs".to_string(),
        })?),
    })
}

/// Why `git count-objects -v` output could not be read.
///
/// Keyed by the field name rather than one variant per key: the set of keys writ
/// reads grew from one to two, and a variant per key per failure mode grows as
/// their product. The name is carried in the message so the diagnostic loses
/// nothing.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CountObjectsParseError {
    #[error("git count-objects -v output has no `{key}:` line")]
    MissingKey { key: String },
    #[error("git count-objects -v output has more than one `{key}:` line")]
    DuplicateKey { key: String },
    #[error("git count-objects -v reported a non-numeric `{key}` value {raw:?}")]
    UnparseableValue { key: String, raw: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The shape git 2.54 actually emits, used as the base for tests that vary
    /// one thing about it. Verified against real `git count-objects -v` output
    /// for a fresh bare repo, a repo with only loose objects, and a packed one.
    fn real_output(count: u64, packs: u64) -> String {
        format!(
            "count: {count}\nsize: 12\nin-pack: 2\npacks: {packs}\nsize-pack: 1\nprune-packable: 0\ngarbage: 0\nsize-garbage: 0\n"
        )
    }

    fn counts(loose_objects: u64, packs: u64) -> ObjectCounts {
        ObjectCounts {
            loose_objects: LooseObjectCount::new(loose_objects),
            packs: PackCount::new(packs),
        }
    }

    fn threshold(loose_objects: u64, packs: u64) -> CompactionThreshold {
        CompactionThreshold::new(LooseObjectCount::new(loose_objects), PackCount::new(packs))
    }

    #[test]
    fn parses_the_output_git_actually_emits() {
        assert_eq!(
            parse_count_objects_verbose(&real_output(3, 1)).unwrap(),
            counts(3, 1),
        );
    }

    #[test]
    fn tolerates_an_alternate_line_whose_value_is_not_a_number() {
        // `count-objects -v` prints one `alternate:` line per configured
        // alternate object store. A parser that required numeric values would
        // reject every repo that has one.
        let out = format!("{}alternate: /srv/shared/objects\n", real_output(7, 2));
        assert_eq!(parse_count_objects_verbose(&out).unwrap(), counts(7, 2));
    }

    #[test]
    fn tolerates_unknown_keys_blank_lines_and_reordering() {
        let out = "\nsize-garbage: 0\nfuture-key: whatever\n\ncount: 42\npacks: 9\n";
        assert_eq!(parse_count_objects_verbose(out).unwrap(), counts(42, 9));
    }

    #[test]
    fn is_not_confused_by_keys_that_merely_contain_a_read_key() {
        // `prune-packable` and `size-pack` are real keys; a substring match
        // would be fine today, but a future `loose-count:` or `cruft-packs:`
        // would not be.
        let out = "loose-count: 999\nrecount: 888\ncruft-packs: 7\ncount: 5\npacks: 2\n";
        assert_eq!(parse_count_objects_verbose(out).unwrap(), counts(5, 2));
    }

    /// Both keys are required, and each names itself when missing.
    ///
    /// `packs` is as required as `count`, which is a real strengthening: before
    /// the pack threshold, output without a `packs:` line parsed fine. Git emits
    /// it unconditionally (`packs: 0` on a fresh repo), so requiring it costs
    /// nothing and is what makes a shape change loud rather than silently
    /// disabling half the policy.
    #[test]
    fn rejects_output_missing_either_key() {
        for (out, missing) in [
            ("size: 12\npacks: 1\n", "count"),
            ("count: 3\nsize: 12\n", "packs"),
        ] {
            assert_eq!(
                parse_count_objects_verbose(out).unwrap_err(),
                CountObjectsParseError::MissingKey {
                    key: missing.to_string(),
                },
                "{out:?}",
            );
        }
    }

    #[test]
    fn rejects_a_non_numeric_value_for_either_key() {
        for (out, key, raw) in [
            ("count: banana\npacks: 1\n", "count", "banana"),
            ("count: 3\npacks: lots\n", "packs", "lots"),
            // Not a thing git emits, but `-1` parsed as a `u64` failure rather
            // than wrapping to `u64::MAX` is the difference between "refuse" and
            // "compact immediately, forever".
            ("count: -1\npacks: 1\n", "count", "-1"),
            ("count: 3\npacks: -1\n", "packs", "-1"),
        ] {
            assert_eq!(
                parse_count_objects_verbose(out).unwrap_err(),
                CountObjectsParseError::UnparseableValue {
                    key: key.to_string(),
                    raw: raw.to_string(),
                },
                "{out:?}",
            );
        }
    }

    #[test]
    fn rejects_duplicated_lines_for_either_key() {
        for (out, key) in [
            ("count: 1\ncount: 2\npacks: 1\n", "count"),
            ("count: 1\npacks: 1\npacks: 2\n", "packs"),
        ] {
            assert_eq!(
                parse_count_objects_verbose(out).unwrap_err(),
                CountObjectsParseError::DuplicateKey {
                    key: key.to_string(),
                },
                "{out:?}",
            );
        }
    }

    /// The thresholds are git's, not writ's, and differ by two orders of
    /// magnitude. Pinned because they are the whole justification for not
    /// inventing our own: a silent edit here would be writ claiming to know
    /// better than upstream without saying so.
    #[test]
    fn the_defaults_are_gits_own() {
        assert_eq!(
            CompactionThreshold::GIT_DEFAULT,
            threshold(6700, 50),
            "git 6700 loose objects, 50 packs",
        );
    }

    proptest! {
        /// Round trip: any pair of counts git could report is recovered exactly.
        #[test]
        fn any_counts_round_trip_through_the_real_output_shape(loose: u64, packs: u64) {
            prop_assert_eq!(
                parse_count_objects_verbose(&real_output(loose, packs)).unwrap(),
                counts(loose, packs),
            );
        }

        /// The whole of the policy, stated independently of how `decide` is
        /// written: compact exactly when *either* axis reaches its threshold.
        ///
        /// Over the *whole* domain. This does not on its own pin the boundary —
        /// see the two properties below for why.
        #[test]
        fn decide_compacts_exactly_when_either_axis_reaches_its_threshold(
            loose: u64,
            packs: u64,
            loose_threshold: u64,
            pack_threshold: u64,
        ) {
            let decision = decide(
                counts(loose, packs),
                threshold(loose_threshold, pack_threshold),
            );
            let compacted = matches!(decision, CompactionDecision::Compact { .. });
            prop_assert_eq!(compacted, loose >= loose_threshold || packs >= pack_threshold);
        }

        /// The same statement over a small domain, so equality on each axis
        /// actually occurs.
        ///
        /// The wide-domain version above looks like it covers this and does not:
        /// two independent uniform `u64`s collide with probability about
        /// 2^-64, so it never once evaluates the case that distinguishes `>=`
        /// from `>`. Mutation testing is what surfaced that on the loose-object
        /// axis; the pack axis inherits the lesson rather than relearning it.
        #[test]
        fn decide_agrees_with_the_policy_on_a_domain_dense_enough_to_hit_equality(
            loose in 0u64..8,
            packs in 0u64..8,
            loose_threshold in 1u64..8,
            pack_threshold in 1u64..8,
        ) {
            let decision = decide(
                counts(loose, packs),
                threshold(loose_threshold, pack_threshold),
            );
            let compacted = matches!(decision, CompactionDecision::Compact { .. });
            prop_assert_eq!(compacted, loose >= loose_threshold || packs >= pack_threshold);
        }

        /// **Each axis fires on its own.** The pack threshold is not decoration
        /// on the loose-object one: bailiff's repo grows by whole packs and
        /// would sit under any loose-object threshold indefinitely, so a policy
        /// where packs could only trigger *alongside* loose objects would be the
        /// old loose-only policy wearing a second field.
        ///
        /// Held at zero on the other axis, so the axis under test is provably
        /// the only thing that can have fired.
        #[test]
        fn either_axis_alone_triggers_a_compaction(over in 1u64..64, under in 0u64..64) {
            let by_packs = decide(counts(0, over), threshold(u64::MAX, over));
            prop_assert!(
                matches!(
                    by_packs,
                    CompactionDecision::Compact { trigger: CompactionTrigger::Packs, .. },
                ),
                "packs alone must trigger: {by_packs:?}",
            );

            let by_loose = decide(counts(over, 0), threshold(over, u64::MAX));
            prop_assert!(
                matches!(
                    by_loose,
                    CompactionDecision::Compact { trigger: CompactionTrigger::LooseObjects, .. },
                ),
                "loose objects alone must trigger: {by_loose:?}",
            );

            // ...and neither axis fires for the other's sake.
            let neither = decide(counts(under, under), threshold(u64::MAX, u64::MAX));
            prop_assert!(matches!(neither, CompactionDecision::Skip { .. }), "{neither:?}");
        }

        /// The trigger names exactly the axes that were over, which is what an
        /// operator log line claims and what `made_progress` is judged against.
        #[test]
        fn the_trigger_names_exactly_the_axes_that_were_over(
            loose in 0u64..8,
            packs in 0u64..8,
            loose_threshold in 1u64..8,
            pack_threshold in 1u64..8,
        ) {
            let decision = decide(
                counts(loose, packs),
                threshold(loose_threshold, pack_threshold),
            );
            let expected = match (loose >= loose_threshold, packs >= pack_threshold) {
                (false, false) => None,
                (true, false) => Some(CompactionTrigger::LooseObjects),
                (false, true) => Some(CompactionTrigger::Packs),
                (true, true) => Some(CompactionTrigger::Both),
            };
            let actual = match decision {
                CompactionDecision::Skip { .. } => None,
                CompactionDecision::Compact { trigger, .. } => Some(trigger),
            };
            prop_assert_eq!(actual, expected);
        }

        /// The boundary, pinned directly for every threshold on each axis: at
        /// the threshold compact, one below skip. This is the sharpest form of
        /// the "at-or-above, not strictly-above" claim in `decide`'s docstring,
        /// and the assertion that kills a `>` regression outright.
        #[test]
        fn decide_compacts_at_each_threshold_and_skips_one_below(t in 1u64..u64::MAX) {
            // The other axis is held unreachable so it cannot mask the result.
            for (at, below, threshold) in [
                (counts(t, 0), counts(t - 1, 0), threshold(t, u64::MAX)),
                (counts(0, t), counts(0, t - 1), threshold(u64::MAX, t)),
            ] {
                prop_assert!(
                    matches!(decide(at, threshold), CompactionDecision::Compact { .. }),
                    "a count equal to the threshold must compact: {at:?}",
                );
                prop_assert!(
                    matches!(decide(below, threshold), CompactionDecision::Skip { .. }),
                    "one below the threshold must skip: {below:?}",
                );
            }
        }

        /// Whichever branch fires carries the measurement through unchanged, so
        /// the shell can log what it saw without measuring a second time.
        #[test]
        fn decide_carries_the_observed_counts_into_either_branch(
            loose: u64,
            packs: u64,
            loose_threshold: u64,
            pack_threshold: u64,
        ) {
            let observed = counts(loose, packs);
            let decision = decide(observed, threshold(loose_threshold, pack_threshold));
            let carried = match decision {
                CompactionDecision::Skip { counts } | CompactionDecision::Compact { counts, .. } => counts,
            };
            prop_assert_eq!(carried, observed);
        }

        /// A threshold of zero always compacts. This is what the behavioural
        /// tests rely on to provoke a real `git gc` from a handful of notes.
        ///
        /// `Just(0)` is in the strategy on purpose: a bare `any::<u64>()` never
        /// generates the empty repo, which is the one case where "always" is
        /// doing any work.
        #[test]
        fn a_zero_threshold_always_compacts(
            loose in prop_oneof![Just(0u64), 1u64..1_000, any::<u64>()],
            packs in prop_oneof![Just(0u64), 1u64..1_000, any::<u64>()],
        ) {
            let decision = decide(counts(loose, packs), threshold(0, 0));
            prop_assert!(
                matches!(decision, CompactionDecision::Compact { .. }),
                "a zero threshold must always compact",
            );
        }

        /// Progress is a strict decrease **on every axis that was over its
        /// threshold**, and only on those.
        ///
        /// Stated over a dense domain so `after == before` — the case the whole
        /// check exists for — actually occurs.
        #[test]
        fn progress_is_a_strict_decrease_on_every_axis_that_triggered(
            loose_before in 1u64..8,
            loose_after in 0u64..8,
            packs_before in 1u64..8,
            packs_after in 0u64..8,
            loose_threshold in 1u64..8,
            pack_threshold in 1u64..8,
        ) {
            let t = threshold(loose_threshold, pack_threshold);
            let progressed = made_progress(
                counts(loose_before, packs_before),
                counts(loose_after, packs_after),
                t,
            );
            let loose_ok = loose_before < loose_threshold || loose_after < loose_before;
            let packs_ok = packs_before < pack_threshold || packs_after < packs_before;
            prop_assert_eq!(progressed, loose_ok && packs_ok);
        }

        /// **The regression the pack axis introduces, pinned.**
        ///
        /// A repo that trips the pack threshold with *no loose objects at all*
        /// is the ordinary shape of a fetch-heavy repo. Judging its compaction
        /// by the loose-object count would call every such `gc` effective —
        /// `before.loose == 0` reads as "no progress was available" — so the
        /// retry gate would never close and the repo would run a full `gc` on
        /// every request, forever. That is precisely the failure `made_progress`
        /// exists to prevent, reachable only through the axis this change adds.
        #[test]
        fn a_pack_triggered_gc_that_consolidates_nothing_is_not_progress(packs in 1u64..64) {
            let t = threshold(u64::MAX, packs);
            prop_assert!(
                !made_progress(counts(0, packs), counts(0, packs), t),
                "an unmoved pack count with no loose objects must read as ineffective",
            );
            // ...and one that does consolidate is progress, so the check is not
            // simply always-false.
            prop_assert!(made_progress(counts(0, packs), counts(0, packs - 1), t));
        }

        /// An axis already at zero never counts as having failed to progress,
        /// whatever the call reports afterwards. There was no progress available
        /// to make on it, so its absence is not evidence of an ineffective `gc`.
        /// Reachable only through a zero threshold, which is a test's way of
        /// saying "always compact".
        #[test]
        fn an_empty_axis_always_counts_as_progress(loose_after: u64, packs_after: u64) {
            prop_assert!(
                made_progress(counts(0, 0), counts(loose_after, packs_after), threshold(0, 0)),
                "a repo with nothing to pack cannot have stalled",
            );
        }
    }
}
