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
//! [`CompactionThreshold::GIT_DEFAULT`] is git's own pair, expressed in this
//! module's units: `gc.auto`'s 6700 loose objects and `gc.autoPackLimit`'s 50
//! packs, each +1 because git phrases both as *more than* while a threshold here
//! is the count *at which* writ compacts. The intent is to do what git would
//! have done, at the point git would have done it, but synchronously and under
//! the lock writ already holds for every other mutation of the repo.
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
//! two agree. The pack count is exact on both sides, but is read from the pack
//! directory rather than from `count-objects -v`: git's limit counts only local
//! packs without a `.keep` sidecar, and that line counts every pack.

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
    /// Git's own trigger points, expressed in this type's units.
    ///
    /// Not numbers writ invented. Git applies its equivalents to every repo that
    /// has not disabled auto-maintenance, so these are the figures this repo
    /// would have been compacted at before writ suppressed git's background
    /// writer. Choosing our own would mean claiming to know better than upstream
    /// about a tradeoff (lookup cost vs. repack cost) that upstream has tuned
    /// against far more repositories than writ will ever see.
    ///
    /// **The +1 is not a fencepost slip.** Git phrases both knobs as *more
    /// than*: `gc.auto` is documented as "approximately more than this many
    /// loose objects", and `gc.autoPackLimit` as "more than this many packs
    /// that are not marked with `*.keep`" — `too_many_packs()` compares
    /// `limit < count`. A [`CompactionThreshold`] is the count *at which* writ
    /// compacts (see `decide`, which is at-or-above so that a threshold of
    /// zero means "always"), so git's `N` becomes writ's `N + 1` and the two
    /// fire on exactly the same repos. Spelling the defaults 6700 and 50 here
    /// would make writ compact one object, and one pack, earlier than the policy
    /// it claims to be reproducing.
    pub const GIT_DEFAULT: Self = Self {
        loose_objects: LooseObjectCount::new(6701),
        packs: PackCount::new(51),
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
///
/// **The pack count does not come from here**, even though `count-objects -v`
/// prints a `packs:` line, because that line counts every pack. Git's own
/// auto-pack policy counts only *local* packs *not marked with a `.keep`
/// sidecar* — see [`count_unkept_packs`], which reads the pack directory
/// instead.
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

/// How many of a pack directory's packs count towards the auto-pack limit,
/// given its file names.
///
/// **`.keep` packs are excluded, and that is what git does.** A `<name>.keep`
/// sidecar marks its pack as one the repo wants left alone; `too_many_packs()`
/// skips exactly those. Counting them would mean a repo holding 51 kept packs
/// compacts on every request forever: the `gc` cannot consolidate what it is
/// forbidden to touch, so the count never falls, `made_progress` closes the
/// retry gate, and an hour later it happens again. Nothing in writ writes a
/// `.keep`, so this is a guard rather than a fix for an observed failure — but a
/// policy that claims to reproduce git's and diverges on the one case git
/// singles out is a policy whose docstring is wrong.
///
/// Pure, taking names rather than a path, so the rule is testable without
/// building a repo full of packs. The shell reads the directory.
///
/// Reading the directory is also *more* faithful than `count-objects -v`'s
/// `packs:` line in a second way: git counts only packs local to this repo, and
/// `<repo>/objects/pack` is exactly those.
pub fn count_unkept_packs<'a>(names: impl IntoIterator<Item = &'a str>) -> PackCount {
    let mut packs: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut kept: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for name in names {
        if let Some(stem) = name.strip_suffix(".pack") {
            packs.insert(stem);
        } else if let Some(stem) = name.strip_suffix(".keep") {
            kept.insert(stem);
        }
    }
    PackCount::new(packs.difference(&kept).count() as u64)
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
            LooseObjectCount::new(3),
        );
    }

    #[test]
    fn tolerates_an_alternate_line_whose_value_is_not_a_number() {
        // `count-objects -v` prints one `alternate:` line per configured
        // alternate object store. A parser that required numeric values would
        // reject every repo that has one.
        let out = format!("{}alternate: /srv/shared/objects\n", real_output(7, 2));
        assert_eq!(
            parse_count_objects_verbose(&out).unwrap(),
            LooseObjectCount::new(7),
        );
    }

    #[test]
    fn tolerates_unknown_keys_blank_lines_and_reordering() {
        let out = "\nsize-garbage: 0\nfuture-key: whatever\n\ncount: 42\npacks: 9\n";
        assert_eq!(
            parse_count_objects_verbose(out).unwrap(),
            LooseObjectCount::new(42),
        );
    }

    #[test]
    fn is_not_confused_by_keys_that_merely_contain_count() {
        // `prune-packable` and `size-pack` are real keys; a substring match on
        // "count" would be fine today, but a future `loose-count:` would not be.
        let out = "loose-count: 999\nrecount: 888\ncount: 5\n";
        assert_eq!(
            parse_count_objects_verbose(out).unwrap(),
            LooseObjectCount::new(5),
        );
    }

    #[test]
    fn rejects_output_with_no_count_line() {
        assert_eq!(
            parse_count_objects_verbose("size: 12\npacks: 1\n").unwrap_err(),
            CountObjectsParseError::MissingCount,
        );
    }

    #[test]
    fn rejects_a_non_numeric_count() {
        assert_eq!(
            parse_count_objects_verbose("count: banana\n").unwrap_err(),
            CountObjectsParseError::UnparseableCount {
                raw: "banana".to_string(),
            },
        );
    }

    #[test]
    fn rejects_a_negative_count() {
        // Not a thing git emits, but `-1` parsed as a `u64` failure rather than
        // wrapping to `u64::MAX` is the difference between "refuse" and
        // "compact immediately, forever".
        assert_eq!(
            parse_count_objects_verbose("count: -1\n").unwrap_err(),
            CountObjectsParseError::UnparseableCount {
                raw: "-1".to_string(),
            },
        );
    }

    #[test]
    fn rejects_duplicated_count_lines() {
        assert_eq!(
            parse_count_objects_verbose("count: 1\ncount: 2\n").unwrap_err(),
            CountObjectsParseError::DuplicateCount,
        );
    }

    /// **A kept pack does not count towards the limit**, which is the one case
    /// git's own policy singles out.
    ///
    /// Counting it would mean a repo holding enough kept packs compacts on every
    /// request for ever: `gc` cannot consolidate what it may not touch, so the
    /// count never falls and the retry gate reopens an hour later to try again.
    #[test]
    fn kept_packs_do_not_count_towards_the_limit() {
        let names = [
            "pack-aaa.pack",
            "pack-aaa.idx",
            "pack-bbb.pack",
            "pack-bbb.keep",
            "pack-ccc.pack",
            "pack-ccc.idx",
            "pack-ccc.rev",
            // A stray keep with no pack beside it counts nothing either way.
            "pack-ddd.keep",
        ];
        assert_eq!(
            count_unkept_packs(names),
            PackCount::new(2),
            "only pack-aaa and pack-ccc are unkept",
        );
    }

    #[test]
    fn an_empty_pack_directory_has_no_packs() {
        assert_eq!(count_unkept_packs([]), PackCount::new(0));
        // `.idx`/`.rev`/`.mtimes` siblings and the `pack` subdirectory's own
        // odds and ends are not packs.
        assert_eq!(
            count_unkept_packs(["pack-aaa.idx", "pack-aaa.rev", "tmp_pack_x"]),
            PackCount::new(0),
        );
    }

    /// The defaults are git's trigger points, not writ's, and the +1 on each is
    /// load-bearing rather than a fencepost slip.
    ///
    /// Git documents both knobs as *more than* N — 6700 loose objects, 50 packs
    /// — while a threshold here is the count *at which* writ compacts. So 6701
    /// and 51 make the two fire on exactly the same repos, and 6700/50 would
    /// make writ compact one object and one pack earlier than the policy it
    /// claims to reproduce. Pinned because the numbers are the whole
    /// justification for not inventing our own.
    #[test]
    fn the_defaults_fire_where_git_fires() {
        assert_eq!(CompactionThreshold::GIT_DEFAULT, threshold(6701, 51));

        // Stated behaviourally as well as numerically, since that is the claim.
        for (at_gits_limit, one_past) in [
            (counts(6700, 0), counts(6701, 0)),
            (counts(0, 50), counts(0, 51)),
        ] {
            assert!(
                matches!(
                    decide(at_gits_limit, CompactionThreshold::GIT_DEFAULT),
                    CompactionDecision::Skip { .. },
                ),
                "git does not compact *at* its limit, only past it: {at_gits_limit:?}",
            );
            assert!(
                matches!(
                    decide(one_past, CompactionThreshold::GIT_DEFAULT),
                    CompactionDecision::Compact { .. },
                ),
                "one past git's limit must compact: {one_past:?}",
            );
        }
    }

    proptest! {
        /// Round trip: any count git could report is recovered exactly.
        #[test]
        fn any_count_round_trips_through_the_real_output_shape(loose: u64, packs: u64) {
            prop_assert_eq!(
                parse_count_objects_verbose(&real_output(loose, packs)).unwrap(),
                LooseObjectCount::new(loose),
            );
        }

        /// Unkept packs are exactly the `.pack` names with no `.keep` sibling,
        /// stated independently of how the counter is written.
        #[test]
        fn unkept_packs_are_the_packs_without_a_keep_sibling(
            stems in prop::collection::hash_set("[a-c]{1,2}", 0..6),
            kept in prop::collection::hash_set("[a-c]{1,2}", 0..6),
        ) {
            let mut names: Vec<String> = stems.iter().map(|s| format!("pack-{s}.pack")).collect();
            names.extend(kept.iter().map(|s| format!("pack-{s}.keep")));
            // Siblings that are neither, to make sure they are ignored.
            names.extend(stems.iter().map(|s| format!("pack-{s}.idx")));

            let expected = stems.difference(&kept).count() as u64;
            prop_assert_eq!(
                count_unkept_packs(names.iter().map(String::as_str)),
                PackCount::new(expected),
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
