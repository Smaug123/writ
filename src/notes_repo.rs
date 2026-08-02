//! Bare-repo helpers shared by writ and bailiff for note storage.
//!
//! Under the cross-daemon ownership model pinned in slice B4 of
//! `docs/plans/2026-05-14-bailiff-split.md`, each daemon owns its own
//! host-side bare repo: writ persists every signed run as a Git note
//! in its repo, bailiff curates plan-shaped views in its repo, and
//! bailiff fetches writ's notes refs as a Git remote rather than
//! writing into a shared repo. This module is the thin wrapper both
//! daemons use to open their repo, validate it matches the shape they
//! expect, and attach note bodies to per-run seed OIDs under
//! caller-supplied notes refs.
//!
//! ## Threat model
//!
//! Each daemon *owns* the bare repo it writes into and is the sole
//! writer (via this module). The validation below defends against
//! operator error and on-disk corruption, not against an attacker who
//! can write to the daemon's filesystem: a host that can mutate the
//! repo can also forge the signing key, so adversarial-config
//! rejections buy nothing on top. The minimum check surface — pinned
//! at the top of the slice before any code was written — is:
//!
//! * `HEAD` present (a directory with no HEAD is not a Git repo).
//! * `core.bare = true` via `git config --bool --get`, which uses
//!   Git's own parser and gives us last-wins handling for free.
//! * `objects/` and `refs/` exist as directories (so the bare layout
//!   is at least plausibly intact).
//! * `commondir` is absent at the top level (a worktree of a different
//!   repo would have this file and is not what a `NotesRepo` is meant
//!   to write into).
//! * `extensions.objectformat` is unset or `sha1`. Wire-level
//!   `GitObjectId` is 40-hex, so a SHA-256 repo would surface as a
//!   parse failure later — rejecting at open time turns that into an
//!   actionable boot error.
//!
//! Concurrency: every `write_note` call takes a process-wide mutex
//! keyed on the canonical repo path. `git notes add` is not safe under
//! concurrent invocation on the same ref — colliding writes silently
//! lose notes — and serialising at the only writer keeps that
//! property load-bearing instead of relying on operator discipline.
//! `fetch_from_remote` and `compact_if_needed` take the same lock: any
//! mutation of the repo goes through it, with no exceptions for the
//! ones that only rearrange objects.
//!
//! ## Compaction
//!
//! Writ suppresses git's background auto-maintenance in the repos it
//! owns (`writ_core::git_env`), which means nothing packs them unless
//! writ asks. `compact_if_needed` is where it asks; see its docstring
//! for what holds still while a repack runs and why it is inline
//! rather than backgrounded.
//!
//! Host-config isolation: every child `git` runs under `env_clear`
//! plus the shared hardened recipe (`writ_core::git_env`, applied via
//! `apply_clean_git_config` — see there for what each variable denies
//! and why the list is not repeated here). So neither an inherited
//! `GIT_DIR` / `GIT_DEFAULT_HASH` nor a host-wide
//! `safe.bareRepository` / `init.defaultObjectFormat` setting can
//! subvert the owning daemon's repo.
//! We then point git at the repo via `--git-dir=<canonical_path>`
//! instead of bare-repo discovery, which a hardened host can
//! disable. See the `prepare_git_command` helper.
//!
//! The set of env vars to inherit (just `PATH` today) is captured at
//! construct time as an `InheritedEnv` value rather than read
//! implicitly inside command builders. Production code uses
//! `InheritedEnv::from_process`; tests can pass synthetic values and
//! inspect the resulting `Command` without mutating real process env.
//!
//! ## Resource bounds
//!
//! Every child `git` runs under `crate::process_supervisor`, so each
//! invocation carries a wall-clock deadline (`NOTES_GIT_TIMEOUT`), a
//! stdout cap (`NOTES_GIT_STDOUT_CAP`), a tail-capped stderr, and a
//! process-group SIGKILL on the way out.
//!
//! This module used to have a spawn retry and none of the above, while
//! the broker's `clean_git` had all of the above and no spawn retry —
//! two carefully-built disciplines with no overlap, each looking
//! complete where it was defined. The consequence here was concrete:
//! bailiff drives these calls as workflow steps, so a `git` that wedged
//! (a fetch source on a stalled filesystem, a stuck `index.lock`) hung
//! a workflow forever with no diagnosis, and a `for-each-ref` over a
//! corrupted ref namespace could buffer without bound. The spawn retry
//! now comes from `crate::process_spawn` and the supervision from
//! `process_supervisor`, so neither can drift from the other callers
//! again.
//!
//! ## Replaying a killed invocation
//!
//! macOS occasionally discards a freshly spawned child (see `FLAKE.md`), and
//! `process_supervisor` reports the signature of that event. It is only a
//! signature: the probe behind it cannot distinguish a child that never started
//! from one that ran, took effect, and was killed unreaped. So every invocation
//! here passes an explicit `OnBornDead`, and each `Retry` is justified where it is
//! written by a property of that argv — content-addressed, convergent, or refused
//! outright on a second run. Adding a mutating invocation means making that
//! judgement, because the argument is never "this child did nothing".

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};

use self::compaction::{CompactionDecision, CompactionThreshold, ObjectCounts};
use crate::core::{NotesRef, NotesRefError};
use crate::process_supervisor::{self, StderrMode, StdoutMode, SupervisedOutcome, SupervisorError};
use crate::vm_git::{GitObjectId, GitObjectIdError};

/// Wall-clock bound on any single `git` invocation this module makes.
///
/// Every command here is local: a `notes add`, a `hash-object`, a
/// `for-each-ref`, or a `fetch` from a filesystem path. None has any business
/// taking minutes, but "local" is not the same as "cannot wedge" — a fetch source
/// on a stalled network filesystem, a `.git` holding a fifo, or a stuck lock file
/// all hang git indefinitely. Bailiff drives these calls as workflow steps, so an
/// unbounded wait is a workflow that stops with no diagnosis. Generous enough that
/// a loaded host never trips it; finite so a wedged host fails visibly instead.
const NOTES_GIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Cap on captured stdout from a `notes_repo` git command.
///
/// The largest legitimate output is a `for-each-ref` listing of the notes
/// namespace — one refname plus an object id per line, so ~100 bytes per note.
/// 64 MiB is far more than any real namespace and still bounds a corrupted repo
/// (or a `git` that streams garbage) to something the host can hold. Exceeding it
/// fails the call rather than truncating: `for-each-ref` output is parsed one
/// refname per line, and a truncated prefix would read as a complete, shorter
/// listing — silently losing notes.
const NOTES_GIT_STDOUT_CAP: usize = 64 * 1024 * 1024;

/// Bound on retained stderr, re-exported from the supervisor so the tests assert
/// against the same number the drain actually enforces.
#[cfg(test)]
use crate::process_supervisor::STDERR_CAPTURE_TAIL_CAP as NOTES_GIT_STDERR_TAIL_CAP;

/// Attempts allowed for a child matching the phantom-SIGKILL signature (see
/// [`crate::process_supervisor::matches_born_dead_signature`]).
///
/// An attempt count is right here, where a deadline is right for a transient
/// spawn *refusal*: a refusal clears on the host's schedule, so we wait it out;
/// a born-dead child is a per-spawn lottery at roughly 1-in-2000, so what we
/// want is another ticket, not a wait. Three attempts put the residual odds past
/// 1-in-10^10.
const BORN_DEAD_RETRY_ATTEMPTS: usize = 3;

/// The exact `git` invocation [`NotesRepo::compact_if_needed`] uses to pack a
/// repo, pinned as a constant because *which* flags are absent is the
/// load-bearing part.
///
/// The prune date is *stated*, not inherited. The two-week grace on
/// unreferenced objects is the only concurrent-writer mitigation this repo
/// benefits from — git-gc(1) lists two, and the other one, reflog retention,
/// does not apply, because these repos are bare and `core.logAllRefUpdates`
/// defaults to false in a bare repo, so a ref update here writes no reflog at
/// all. Writ therefore cannot afford for the grace to be a default that
/// something else can move.
///
/// And something else can. The hardened recipe silences the system and global
/// config files; nothing silences `<repo>/config`, by design. Measured on git
/// 2.54: with `gc.pruneExpire=now` set there, a plain `gc --quiet` prunes a
/// freshly-written unreferenced object immediately, and passing
/// `--prune=2.weeks.ago` overrides it and the object survives. Writing the
/// default out on the command line is what makes the documented grace a
/// property of this invocation rather than of the repo it happens to run in.
///
/// `--cruft` is imposed for the same reason and against the same weakness.
/// Measured on git 2.54: with `gc.cruftPacks=false` in `<repo>/config`, a `gc`
/// leaves young unreachable objects loose, so it returns success having moved the
/// count not at all — and writ's seed blobs are exactly such objects. Because
/// success leaves the retry gate open, that is a full repack on every subsequent
/// request until the blobs age out. `--cruft` restores the packing this policy
/// assumes.
///
/// Where this stops: writ imposes the settings its documented guarantees rest on
/// — the prune grace that protects a concurrent writer, and the cruft packing
/// that makes compaction actually reduce the count — and no others. Repo-local
/// config can still make a `gc` slower or pack less tightly. That is a
/// performance matter, not a broken guarantee, and chasing every knob would be
/// re-implementing git's configuration in argv.
///
/// Two flags must never appear, and a test asserts each one's absence:
///
/// * `--aggressive`. Unbounded CPU while holding the notes-write mutex, in
///   exchange for a better packing of a repo whose contents are already small
///   signed blobs.
/// * `--force`. That is exactly the override that defeats the `gc.pid` lock
///   described on [`NotesRepo::compact_if_needed`], which is what makes
///   concurrent compaction of one repo impossible rather than merely unlikely.
///
/// `gc` rather than `maintenance run` for the same reason: `maintenance` repacks
/// via `multi-pack-index` without consulting `gc.pid`, so two `maintenance`
/// children — or a `maintenance` and a `gc` — do not exclude each other. Only
/// `gc` participates in the lock.
const GC_ARGV: [&str; 4] = ["gc", "--quiet", GC_PRUNE_GRACE, "--cruft"];

/// Wall-clock bound on the repack in [`NotesRepo::compact_if_needed`], in place
/// of the [`NOTES_GIT_TIMEOUT`] every other invocation here takes.
///
/// Compaction is the one command in this module whose *legitimate* cost grows
/// with the repo's total history: a plain `gc` rewrites all packs, while the
/// threshold that fires it counts only the recent backlog. Bounding it like a
/// `notes add` is what let a repo grow large enough that no attempt could ever
/// finish, at which point compaction stops working permanently — the retry gate
/// bounds the waste but cannot make the work fit.
///
/// So this deadline is not sized to a legitimate repack; it is sized to be past
/// any of them, and its job is to catch a *wedged* git (a stuck lock file, a
/// stalled object directory) rather than a busy one. Measured on git 2.54: a
/// 3000-commit bare repo with 320 loose objects packs in 0.158s, so at that
/// shape 120s corresponds to somewhere around two to three million notes and
/// ten minutes to roughly ten times that. No fixed number survives unbounded
/// history — that is inherent, not an oversight here — but it moves the cliff
/// out past any plausible notes repo.
///
/// The cost of the larger number is paid only in the state that trips it. This
/// holds the notes-write mutex throughout, so a repack killed at the deadline
/// stalls note writes for that long; [`COMPACTION_RETRY_BACKOFF`] then holds off
/// the next attempt, capping it at ten minutes per hour rather than per request.
/// A repo compacting normally never reaches this bound at all.
///
/// ## Why not make the operation cheaper instead
///
/// Because the obvious substitution does not work, which is worth recording so
/// it is not re-proposed. `git repack -d` looks like the fix — pack the loose
/// objects without rewriting existing packs, so cost matches trigger — but writ
/// needs `--cruft`, and git-repack(1) defines `--cruft` as "same as `-a`". A
/// `repack -d --cruft` therefore runs `pack-objects --all --reflog
/// --indexed-objects`, which is a full repack costing the same as the `gc`
/// (measured: 0.100s against `gc`'s 0.158s on the repo above, the difference
/// being `gc`'s cheap extra steps, not the repack).
///
/// And `--cruft` cannot simply be dropped, because [`NotesRepo::write_note`]
/// persists a seed blob per note that nothing ever references — the note is
/// keyed on that blob's id, which appears in the notes tree only as a filename —
/// so every note leaves one permanently unreachable object. A plain `repack -d`
/// leaves those loose (measured: 320 loose objects becomes 20, exactly the
/// unreachable ones), giving the repo a loose-object floor equal to the number
/// of notes ever written. That would make compaction cheap and permanently
/// ineffective, which is worse than expensive and correct.
const COMPACTION_GIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long a failed compaction holds off the next attempt.
///
/// A bound on wasted work, not an estimate of when the cause will clear —
/// nothing here knows that. The failure worth sizing against is a `gc` killed at
/// [`COMPACTION_GIT_TIMEOUT`]: an hour's pause makes that cost at most ten
/// minutes an hour, against ten minutes on *every* agent run with no gate at
/// all. A repo compacting normally never reaches this code, so the pause costs
/// it nothing.
///
/// The ratio is deliberately not held fixed as the repack deadline grows. This
/// number bounds how often writ retries something that just failed, which is a
/// question about the failure, not about how long the attempt was allowed to
/// take; tying them together would mean a longer deadline silently buying a
/// longer blind spot.
const COMPACTION_RETRY_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// The prune date [`GC_ARGV`] imposes: git's own default, spelled out.
///
/// Deliberately identical to git's built-in `gc.pruneExpire` default, so this is
/// not writ inventing a retention policy — it is writ refusing to let the policy
/// be changed underneath it.
const GC_PRUNE_GRACE: &str = "--prune=2.weeks.ago";

/// What to do when an invocation comes back matching the phantom-SIGKILL
/// signature.
///
/// This exists as an explicit per-invocation argument because the signature is
/// evidence, not proof: `getpgid` answers `ESRCH` for an exited-but-unreaped
/// child on this platform, so a child that ran, took effect, and was then killed
/// is indistinguishable from one discarded before it started. See
/// [`crate::process_supervisor::matches_born_dead_signature`].
///
/// Consequently the decision cannot live in the supervisor, which knows nothing
/// about the command, and it must not default: a future mutating invocation added
/// to this module has to choose, and the compiler makes it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum OnBornDead {
    /// Re-run, up to [`BORN_DEAD_RETRY_ATTEMPTS`].
    ///
    /// Only for an invocation whose replay is harmless *on its own merits* —
    /// either idempotent, or one git refuses outright the second time so a
    /// double-apply is impossible. The justification belongs at the call site,
    /// because it is a fact about that argv and not about this module.
    Retry,
    /// Report [`NotesRepoError::GitKilledBeforeCompletion`] instead of re-running.
    ///
    /// For an invocation that could double-apply. Unused today — every invocation
    /// below is replay-safe — but the variant is what makes `Retry` a claim
    /// rather than a default, and gives the next mutating command somewhere
    /// correct to land.
    #[expect(dead_code, reason = "the safe choice for a future mutating invocation")]
    Fail,
}

/// The bounds applied to one supervised `git` invocation.
///
/// A value rather than two loose constants so a caller cannot supply a timeout
/// and forget the cap. Production always uses [`GitLimits::production`]; tests
/// shrink both so a "child floods stdout" case is provoked in milliseconds
/// instead of by spinning a shell against a 64 MiB bound.
#[derive(Copy, Clone, Debug)]
struct GitLimits {
    timeout: Duration,
    stdout_cap: usize,
}

impl GitLimits {
    const fn production() -> Self {
        Self {
            timeout: NOTES_GIT_TIMEOUT,
            stdout_cap: NOTES_GIT_STDOUT_CAP,
        }
    }

    /// The bounds for the repack in [`NotesRepo::compact_if_needed`].
    ///
    /// Same output cap — `gc --quiet` prints nothing on success — and a longer
    /// deadline, for the reason [`COMPACTION_GIT_TIMEOUT`] gives.
    const fn compaction() -> Self {
        Self {
            timeout: COMPACTION_GIT_TIMEOUT,
            stdout_cap: NOTES_GIT_STDOUT_CAP,
        }
    }
}

/// Snapshot of the parent-process environment values that flow into
/// git child commands. Production code captures this once via
/// [`InheritedEnv::from_process`]; tests can construct synthetic
/// instances without mutating real process state.
///
/// Today the only inherited value is `PATH` (needed so the `git`
/// binary itself is locatable). All other variables are either set
/// explicitly to the clean recipe in `prepare_git_command` or wiped
/// by `env_clear`.
#[derive(Clone, Debug)]
pub(crate) struct InheritedEnv {
    path: Option<OsString>,
}

impl InheritedEnv {
    /// Capture the current process's `PATH`.
    pub(crate) fn from_process() -> Self {
        Self {
            path: std::env::var_os("PATH"),
        }
    }
}

/// Result of an idempotent [`NotesRepo::write_note_if_absent`] call:
/// either the operation attached a fresh note, or it observed an
/// existing one at the target OID and did nothing.
///
/// Both variants expose the same target OID so callers can read the
/// note body back regardless of which branch fired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// No note was attached at the seed's target OID; the call wrote
    /// `body` and returns the freshly-attached target.
    Written(GitObjectId),
    /// A note already existed at the seed's target OID; nothing was
    /// written. The wrapped OID matches the one a subsequent
    /// [`NotesRepo::read_note_if_present`] would query.
    AlreadyPresent(GitObjectId),
}

/// What [`NotesRepo::compact_if_needed`] did.
///
/// Returned rather than logged in place: this module has no opinion on how loud
/// a compaction should be, and its callers do — the daemon logs it and carries
/// on, because a note is already durably written by the time compaction runs and
/// failing the request over housekeeping would be the wrong trade.
///
/// Distinct from the internal `CompactionDecision` on purpose. That is the
/// inert *plan* the pure policy produces; this is the *outcome* of interpreting
/// it. Collapsing them would mean the shell returning a value that reads as "we
/// decided to compact" whether or not the repack actually ran.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompactionOutcome {
    /// The repo was under both thresholds; nothing was packed.
    Skipped { counts: ObjectCounts },
    /// A recent attempt failed and the backoff has not elapsed, so this call did
    /// nothing at all — not even measure.
    ///
    /// Not an error: the note write it followed succeeded, and housekeeping writ
    /// is deliberately postponing is not a failed request. Carries no count
    /// because none was taken: `count-objects` is one of the invocations that can
    /// fail, so the gate has to come before it, and reporting a stale figure
    /// would misrepresent when it was read.
    Deferred { retry_in: Duration },
    /// The repo was at or over a threshold and `git gc` ran to completion.
    ///
    /// Both readings are reported because completion is not the same as
    /// effectiveness — a `gc` can return zero and leave the counts exactly where
    /// they were — and an operator reading one number cannot tell the
    /// difference. `trigger` says which axis put the repo over, which is the
    /// difference between "this repo writes a lot" and "this repo fetches a
    /// lot".
    Compacted {
        before: ObjectCounts,
        after: ObjectCounts,
        trigger: compaction::CompactionTrigger,
    },
}

/// A validated handle on a daemon-owned bare notes repo.
///
/// Construct via [`NotesRepo::open`] (validation only) or
/// [`NotesRepo::init_or_open`] (initialise an empty bare repo on
/// first run, then validate). The wrapped path is the canonicalised
/// filesystem location; the canonical form is what the per-repo
/// notes-write mutex is keyed on, so two `NotesRepo` handles for
/// the same on-disk repo share the same lock.
#[derive(Debug)]
pub struct NotesRepo {
    canonical_path: PathBuf,
    inherited_env: InheritedEnv,
}

impl NotesRepo {
    /// Open an existing bare repo at `path` after running the pinned
    /// minimal validation. The path is canonicalised so multiple
    /// handles for the same repo serialise on a shared mutex.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NotesRepoError> {
        Self::open_with_env(path.as_ref(), InheritedEnv::from_process())
    }

    fn open_with_env(path: &Path, inherited_env: InheritedEnv) -> Result<Self, NotesRepoError> {
        let canonical_path =
            path.canonicalize()
                .map_err(|source| NotesRepoError::Canonicalize {
                    path: path.to_path_buf(),
                    source,
                })?;
        validate_bare_layout(&canonical_path, &inherited_env)?;
        Ok(Self {
            canonical_path,
            inherited_env,
        })
    }

    /// Initialise a bare repo at `path` if and only if `path` is absent
    /// or is an existing empty directory, then call [`Self::open`].
    /// An existing non-empty path is opened (and validated) verbatim —
    /// never touched by `git init`.
    ///
    /// This split matters: `git init --bare` against a worktree root or
    /// a worktree's `.git` directory leaves bare-layout files behind
    /// (HEAD, config, objects/, refs/) at the target and can flip
    /// `core.bare` to `true`, silently breaking the worktree. Refusing
    /// to mutate any non-empty existing path makes accidental misuse —
    /// "you pointed me at your repo by mistake" — surface as an
    /// `Open*` validation error instead of as corruption.
    pub fn init_or_open(path: impl AsRef<Path>) -> Result<Self, NotesRepoError> {
        let path = path.as_ref();
        let inherited_env = InheritedEnv::from_process();
        let needs_init = match std::fs::read_dir(path) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(path).map_err(|source| NotesRepoError::CreateDir {
                    path: path.to_path_buf(),
                    source,
                })?;
                true
            }
            Err(source) => {
                return Err(NotesRepoError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if needs_init {
            // `--object-format=sha1` is load-bearing: a host with
            // `init.defaultObjectFormat = sha256` (global config) or
            // `GIT_DEFAULT_HASH=sha256` (env) would otherwise produce
            // a SHA-256 repo that `open` rejects with
            // `UnsupportedObjectFormat`, leaving an unusable
            // directory on disk. Forcing the format keeps the wire-
            // level 40-hex `GitObjectId` invariant intact regardless
            // of the operator's global git setup.
            run_git(
                path,
                ["init", "--bare", "--quiet", "--object-format=sha1"],
                None,
                CaptureOutput::Discard,
                &inherited_env,
                // `git init` on an existing repo re-initialises it: same refs,
                // same objects, same config. Replay reaches the same state.
                OnBornDead::Retry,
            )?;
        }
        Self::open_with_env(path, inherited_env)
    }

    /// Canonical on-disk path the handle resolved to.
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    /// Write `body` as a note attached to a fresh seed blob hashed from
    /// `seed`, under `notes_ref`. Returns the seed blob's OID — the
    /// "target" the note is keyed on, which callers persist so they
    /// can read the note back later.
    ///
    /// `seed` is expected to be unique per note (typically a small
    /// canonical encoding of the run id) so each note attaches to a
    /// distinct OID; the seed blob carries no payload of its own.
    /// The bytes of `body` are the entire signed envelope (output
    /// bytes + signed metadata + signature) — putting them in the
    /// note body, not in a separate blob, keeps them reachable via
    /// the notes ref under clone and fetch.
    ///
    /// Holds the process-wide notes-write mutex for this repo across
    /// the whole operation. Concurrent `git notes add` against the
    /// same ref silently drops one of the writes; serialising at the
    /// only writer is the load-bearing race-correctness check.
    pub fn write_note(
        &self,
        notes_ref: &NotesRef,
        seed: &[u8],
        body: &[u8],
    ) -> Result<GitObjectId, NotesRepoError> {
        // `git notes add -C <oid>` against Git's empty-blob OID
        // (`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`) succeeds without
        // attaching a note, so `write_note` would return a target OID
        // that `read_note` cannot read back. Rejecting empty bodies up
        // front turns the silent gap into a typed error at the only
        // writer.
        if body.is_empty() {
            return Err(NotesRepoError::EmptyBody);
        }
        let _guard = lock_notes_write(&self.canonical_path);
        let target_oid = hash_object_stdin(
            &self.canonical_path,
            seed,
            &self.inherited_env,
            HashWrite::Persist,
        )?;
        // Write the body as a blob first and reference it via `-C
        // <oid>`. `git notes add -F file` runs the body through
        // `stripspace` (strip trailing whitespace per line, collapse
        // blank lines) which corrupts arbitrary bytes — the envelope
        // is binary in general, so we have to bypass stripspace.
        // `-C <existing_blob_oid>` reuses the object verbatim and is
        // the documented escape hatch.
        let body_oid = hash_object_stdin(
            &self.canonical_path,
            body,
            &self.inherited_env,
            HashWrite::Persist,
        )?;
        // `notes add` creates a commit on the notes ref, so it
        // needs an author identity. The shared hardened env recipe we
        // run under deliberately denies git every config source except
        // the repo's local file, so we inject the identity via `-c`
        // flags rather than rely on operator gitconfig. The values are placeholders — the
        // commit author is not part of the audit trail; the signed
        // envelope inside the note body is.
        run_git(
            &self.canonical_path,
            [
                "-c",
                "user.name=bailiff",
                "-c",
                "user.email=bailiff@localhost",
                "notes",
                &format!("--ref={}", notes_ref.as_str()),
                "add",
                "-C",
                body_oid.as_str(),
                target_oid.as_str(),
            ],
            None,
            CaptureOutput::Discard,
            &self.inherited_env,
            // `notes add` without `-f` refuses when an annotation already
            // exists ("Cannot add notes. Found existing notes..."), so a
            // replay cannot double-apply: it either writes the note the
            // killed child did not, or fails loudly. Note the guarantee is
            // *no silent double-apply*, not *no spurious failure* — a child
            // killed between committing the ref and exiting would report the
            // replay's refusal. That is the safe direction.
            OnBornDead::Retry,
        )?;
        Ok(target_oid)
    }

    /// Idempotent variant of [`Self::write_note`]: returns
    /// [`WriteOutcome::AlreadyPresent`] if a note is already attached
    /// at the seed's target OID under `notes_ref`, and only writes
    /// (returning [`WriteOutcome::Written`]) when the target is
    /// currently bare.
    ///
    /// The check-and-write is atomic in-process: both the existence
    /// probe and the eventual write happen while holding the
    /// per-repo notes-write mutex. A concurrent in-process caller
    /// that arrives second observes the first write and returns
    /// `AlreadyPresent`, not a `GitFailed` from `git notes add`.
    /// Across processes the lock does not generalise (a separate
    /// CLI invocation has its own mutex), so the second writer can
    /// still see the in-process check pass and have `notes add`
    /// reject the write; that residual race surfaces as a generic
    /// `NotesRepoError::GitFailed` here. D1 accepts that
    /// limitation; the typical bailiff workflow is sequential
    /// operator commands, not concurrent CLI invocations.
    ///
    /// As with [`Self::write_note`], `body` must be non-empty: the
    /// empty-blob OID corner case in `git notes add -C` would let an
    /// empty body silently fail to attach.
    pub fn write_note_if_absent(
        &self,
        notes_ref: &NotesRef,
        seed: &[u8],
        body: &[u8],
    ) -> Result<WriteOutcome, NotesRepoError> {
        if body.is_empty() {
            return Err(NotesRepoError::EmptyBody);
        }
        let _guard = lock_notes_write(&self.canonical_path);
        let target_oid = hash_object_stdin(
            &self.canonical_path,
            seed,
            &self.inherited_env,
            HashWrite::Persist,
        )?;
        if self.read_note_if_present(notes_ref, &target_oid)?.is_some() {
            return Ok(WriteOutcome::AlreadyPresent(target_oid));
        }
        let body_oid = hash_object_stdin(
            &self.canonical_path,
            body,
            &self.inherited_env,
            HashWrite::Persist,
        )?;
        run_git(
            &self.canonical_path,
            [
                "-c",
                "user.name=bailiff",
                "-c",
                "user.email=bailiff@localhost",
                "notes",
                &format!("--ref={}", notes_ref.as_str()),
                "add",
                "-C",
                body_oid.as_str(),
                target_oid.as_str(),
            ],
            None,
            CaptureOutput::Discard,
            &self.inherited_env,
            // `notes add` without `-f` refuses when an annotation already
            // exists ("Cannot add notes. Found existing notes..."), so a
            // replay cannot double-apply: it either writes the note the
            // killed child did not, or fails loudly. Note the guarantee is
            // *no silent double-apply*, not *no spurious failure* — a child
            // killed between committing the ref and exiting would report the
            // replay's refusal. That is the safe direction.
            OnBornDead::Retry,
        )?;
        Ok(WriteOutcome::Written(target_oid))
    }

    /// Fetch one or more refs from a peer bare repo at `source` into
    /// this repo. `refspecs` follow git's `<src>:<dst>` syntax (with
    /// optional leading `+` for force); each one specifies a ref pair
    /// to mirror locally. The peer is referenced by filesystem path —
    /// git also accepts local paths as URLs — and never persisted
    /// as a named remote, keeping the operation stateless.
    ///
    /// This is the bailiff side of the writ→bailiff handoff. Bailiff
    /// fetches writ's `refs/notes/writ/v1/*` namespace into its own
    /// repo under the same names; once present, the notes are
    /// readable via [`Self::read_note`] under the same target OID
    /// that writ wrote against.
    ///
    /// Holds the process-wide per-repo notes-write mutex across the
    /// fetch. Git's index / refs / objects writes are not safe under
    /// concurrent fetch+notes-add into the same destination, and the
    /// mutex serialises every mutation through the one writer.
    ///
    /// `--no-tags` is unconditional: writ doesn't publish tags, and
    /// fetching them would pollute bailiff's namespace with whatever
    /// happens to be lying around in writ's repo.
    pub fn fetch_from_remote(
        &self,
        source: impl AsRef<Path>,
        refspecs: &[&str],
    ) -> Result<(), NotesRepoError> {
        let source = source.as_ref();
        if refspecs.is_empty() {
            return Err(NotesRepoError::EmptyRefspecs);
        }
        let source_str = source
            .to_str()
            .ok_or_else(|| NotesRepoError::SourcePathNonUtf8 {
                path: source.to_path_buf(),
            })?;
        let _guard = lock_notes_write(&self.canonical_path);
        let mut args: Vec<&str> = vec!["fetch", "--no-tags", source_str];
        args.extend(refspecs.iter().copied());
        run_git(
            &self.canonical_path,
            args,
            None,
            CaptureOutput::Discard,
            &self.inherited_env,
            // A fetch of the same refspecs converges: it writes the same refs to
            // the same object ids, so a second run is a no-op.
            OnBornDead::Retry,
        )?;
        Ok(())
    }

    /// Pack this repo's loose objects, if it has accumulated enough of them to
    /// be worth it.
    ///
    /// Writ suppresses git's own background auto-maintenance in every repo it
    /// owns (see [`writ_core::git_env`]): a detached `git maintenance` child is
    /// a writer writd never spawned, cannot wait for, and whose lifetime no
    /// writd operation bounds. That removed the compaction the repo used to get
    /// for free, so this is where writ does it deliberately instead. Call it
    /// after a note write; it is cheap when there is nothing to do (one
    /// `count-objects -v`) and it decides for itself whether to spend a repack.
    ///
    /// ## What holds still while this runs
    ///
    /// The per-repo notes-write mutex, for the whole measure-and-pack — the same
    /// lock [`Self::write_note`] and [`Self::fetch_from_remote`] take, because
    /// compaction *is* another mutation and gets no special treatment. So
    /// in-process it is fully serialised against every other writer here.
    ///
    /// Across processes the mutex does not generalise (as
    /// [`Self::write_note_if_absent`] already documents), and two further
    /// mechanisms cover what it cannot, both verified against git 2.54 rather
    /// than assumed:
    ///
    /// * **Against another `git gc`:** git's own `<repo>/gc.pid`. A second gc
    ///   whose recorded pid looks live on this host refuses outright — `fatal: gc
    ///   is already running on machine '...' pid N`. So concurrent compaction of
    ///   one repo is impossible, not merely unlikely. (Note this is specific to
    ///   `gc`: `git maintenance` does *not* consult `gc.pid`, which is one more
    ///   reason the argv this runs is a `gc` and not a `maintenance run`.)
    /// * **Against another writer mid-write:** the prune grace period. git-gc(1)
    ///   keeps every object whose mtime is newer than the prune date (two weeks)
    ///   along with everything reachable from it. Our risk window —
    ///   `hash-object` writes a blob, `notes add` references it moments later —
    ///   sits inside that by a factor of about a million. Writ *imposes* that
    ///   date on the command line rather than inheriting it, because the default
    ///   is overridable from `<repo>/config`, which the hardened recipe
    ///   deliberately does not silence. See `GC_ARGV`.
    ///
    /// git's documentation is candid that these "fall short of a complete
    /// solution, so users who run commands concurrently have to live with some
    /// risk of corruption (which seems to be low in practice)". Writ's position
    /// is that this is strictly better than the status quo it replaces: the
    /// writer being removed was an *unsupervised* one racing whatever writd was
    /// doing, and this one is bounded, logged, and serialised against every
    /// in-process writer.
    ///
    /// ## Why not spawn it in the background
    ///
    /// Because that is precisely the thing being fixed. A background compactor
    /// is a second writer in a repo writd owns, and the only difference from
    /// git's detached maintenance would be whose code spawned it. Running
    /// inline costs the one request that crosses the threshold a repack —
    /// roughly one in two thousand, in a request that already takes minutes.
    ///
    /// ## What this does not guarantee
    ///
    /// That the repo stays packed. A plain `gc` rewrites *all* packs, so its cost
    /// grows with total history while the threshold that triggers it counts only
    /// the recent backlog, and no fixed deadline survives unbounded growth. The
    /// `gc` gets `COMPACTION_GIT_TIMEOUT` rather than the module's ordinary
    /// bound precisely because of that mismatch — which moves the point where a
    /// repo becomes permanently uncompactable out past any plausible notes repo,
    /// but does not abolish it. That constant records the measurements, and why
    /// making the operation cheaper instead does not work.
    ///
    /// What is bounded is the damage: `COMPACTION_RETRY_BACKOFF` holds off the
    /// next attempt, so that state costs one killed `gc` per hour rather than one
    /// per request, and writ degrades to the behaviour it had before compaction
    /// existed. The gate covers the whole attempt, not just the repack: it is
    /// consulted before anything runs (measuring is a git invocation against the
    /// same object directory and can itself be the slow thing), it closes on any
    /// failure whichever step raised it, and it closes on a `gc` that returns
    /// success while moving the count not at all — otherwise a full repack per
    /// request for as long as the cause lasts. That "whichever step" is
    /// structural rather than remembered: the inner `attempt_compaction` is not
    /// given the state, so no exit of it can fail to record.
    ///
    /// The stall that buys is real and bounded: this holds the notes-write mutex
    /// throughout, so a repack killed at the deadline blocks note writes for that
    /// long, once per `COMPACTION_RETRY_BACKOFF`.
    pub fn compact_if_needed(&self) -> Result<CompactionOutcome, NotesRepoError> {
        self.compact_if_needed_with(CompactionThreshold::GIT_DEFAULT)
    }

    /// The repo's true loose-object and pack counts, straight from
    /// `count-objects -v`.
    ///
    /// Called twice per compaction — once to decide, once to check the repack
    /// achieved something — so it is one function rather than two spellings of
    /// the same parse. Both axes come from one invocation, which is why they are
    /// one struct: a `before` on one axis paired with an `after` on the other
    /// would compare two different readings.
    fn count_objects(&self) -> Result<ObjectCounts, NotesRepoError> {
        let stdout = run_git(
            &self.canonical_path,
            ["count-objects", "-v"],
            None,
            CaptureOutput::Capture,
            &self.inherited_env,
            // Read-only: it counts files and prints. Nothing to double-apply.
            OnBornDead::Retry,
        )?;
        let text = String::from_utf8(stdout)
            .map_err(|source| NotesRepoError::CountObjectsNonUtf8 { source })?;
        compaction::parse_count_objects_verbose(&text)
            .map_err(|source| NotesRepoError::CountObjectsParse { source })
    }

    /// [`Self::compact_if_needed`] at a caller-chosen threshold. Only tests want
    /// anything other than [`CompactionThreshold::GIT_DEFAULT`]: one policy for
    /// every production caller is what stops the threshold drifting per call
    /// site, which is the same reason the git env recipe lives in one place.
    fn compact_if_needed_with(
        &self,
        threshold: CompactionThreshold,
    ) -> Result<CompactionOutcome, NotesRepoError> {
        self.compact_if_needed_with_limits(threshold, GitLimits::compaction())
    }

    /// [`Self::compact_if_needed_with`] under caller-chosen bounds on the repack.
    ///
    /// Only tests want anything other than [`GitLimits::compaction`], and they
    /// want it for one reason: the motivating failure is a repack killed at its
    /// deadline, which cannot otherwise be provoked without waiting that deadline
    /// out.
    fn compact_if_needed_with_limits(
        &self,
        threshold: CompactionThreshold,
        limits: GitLimits,
    ) -> Result<CompactionOutcome, NotesRepoError> {
        let mut state = lock_notes_write(&self.canonical_path);

        // Read once, under the lock, so the decision and the state it is recorded
        // against cannot disagree.
        let now = SystemTime::now();

        // Before any git runs, not after measuring: `count-objects` is itself an
        // invocation that can be the thing failing (a slow or damaged object
        // directory can hold it to the deadline), and a gate consulted after it
        // would leave exactly that cost on every request.
        if let Some(retry_in) = state.compaction_retry_in(&self.canonical_path, now) {
            return Ok(CompactionOutcome::Deferred { retry_in });
        }

        let outcome = self.attempt_compaction(threshold, limits);

        // The only place the gate is written. Deliberately not at the exits of
        // the attempt above: this rule has three failure paths to cover — the
        // measurement, the repack, and the measurement *after* the repack — and
        // writing it at each of them missed one twice. `attempt_compaction`
        // cannot record anything, because it is not given the state to record it
        // in, so there is no exit left that can forget.
        match &outcome {
            // Ran, and moved nothing. Worse than failing, because nothing else
            // here would stop the next request repacking again.
            Ok(CompactionOutcome::Compacted { before, after, .. })
                if !compaction::made_progress(*before, *after, threshold) =>
            {
                state.hold_off_compaction(&self.canonical_path, now);
            }
            // Cleared rather than left to expire: a repo that is packing
            // successfully must go on packing at whatever rate its loose-object
            // count demands.
            Ok(_) => state.allow_compaction(&self.canonical_path),
            Err(_) => state.hold_off_compaction(&self.canonical_path, now),
        }

        outcome
    }

    /// One compaction attempt: measure, decide, repack, measure again.
    ///
    /// Takes no lock and holds no state — [`Self::compact_if_needed_with`] has
    /// both, and interprets whatever this returns. That split is what makes the
    /// retry gate hard to get wrong: every `?` below is an exit this function
    /// could otherwise have had to remember to record.
    fn attempt_compaction(
        &self,
        threshold: CompactionThreshold,
        limits: GitLimits,
    ) -> Result<CompactionOutcome, NotesRepoError> {
        // Deliberately *not* under `limits`: the longer deadline is for the
        // repack, whose legitimate cost grows with total history. Counting loose
        // objects is a walk of the 256 fanout directories and has no such growth,
        // so widening its bound would only slow down the discovery that the
        // object directory is wedged.
        let counts = self.count_objects()?;

        match compaction::decide(counts, threshold) {
            CompactionDecision::Skip { counts } => Ok(CompactionOutcome::Skipped { counts }),
            CompactionDecision::Compact { counts, trigger } => {
                run_git_with_limits(
                    &self.canonical_path,
                    GC_ARGV,
                    None,
                    CaptureOutput::Discard,
                    &self.inherited_env,
                    limits,
                    // Convergent, and the one invocation here where that needs
                    // saying carefully. A `gc` killed partway leaves the repo
                    // consistent — it writes a new pack and only then unlinks the
                    // objects it copied — so a replay re-does work rather than
                    // double-applying anything. It cannot even collide with the
                    // child it is replacing: that child is dead, so the `gc.pid`
                    // it left behind names a pid that no longer exists and git
                    // treats the lock as stale.
                    OnBornDead::Retry,
                )?;

                // A `gc` can succeed and achieve nothing, so completion is
                // measured rather than assumed. Costs one `count-objects` against
                // a repo that was just packed; the caller decides what an
                // unmoved count means.
                let after = self.count_objects()?;
                Ok(CompactionOutcome::Compacted {
                    before: counts,
                    after,
                    trigger,
                })
            }
        }
    }

    /// Read the body of the note attached to `target_oid` under
    /// `notes_ref`. Errors if no note is attached at that target.
    /// Does not take the notes-write mutex: reads never collide with
    /// each other and the lockless read is what callers want for the
    /// verification path.
    pub fn read_note(
        &self,
        notes_ref: &NotesRef,
        target_oid: &GitObjectId,
    ) -> Result<Vec<u8>, NotesRepoError> {
        // `git notes show` writes the note blob verbatim
        // (`fwrite(buf, 1, size, stdout)` — no implicit trailing
        // newline), and our `write_note` references the body via
        // `-C <blob_oid>` so no stripspace runs on the input side
        // either. The round-trip is byte-exact.
        run_git(
            &self.canonical_path,
            [
                "notes",
                &format!("--ref={}", notes_ref.as_str()),
                "show",
                target_oid.as_str(),
            ],
            None,
            CaptureOutput::Capture,
            &self.inherited_env,
            // Read-only: nothing to double-apply.
            OnBornDead::Retry,
        )
    }

    /// Same byte-exact recovery as [`Self::read_note`] when a note
    /// exists, but folds the two "no note here" cases — `notes_ref`
    /// doesn't exist yet, or it exists but has no annotation at
    /// `target_oid` — into `Ok(None)`. Other failure modes (git not
    /// installed, repo permission errors) still propagate as
    /// `NotesRepoError`.
    ///
    /// Both absent cases share git's same stderr signature
    /// (`error: no note found for object <oid>.`), so we match on
    /// the substring `"no note found for object"`. The phrasing has
    /// been stable since `git notes` shipped and is what gates the
    /// returned `Ok(None)`; an exit-1 failure carrying a different
    /// stderr surfaces unchanged so a genuinely broken repo doesn't
    /// silently masquerade as "absent".
    pub fn read_note_if_present(
        &self,
        notes_ref: &NotesRef,
        target_oid: &GitObjectId,
    ) -> Result<Option<Vec<u8>>, NotesRepoError> {
        match self.read_note(notes_ref, target_oid) {
            Ok(body) => Ok(Some(body)),
            Err(NotesRepoError::GitFailed { stderr, .. })
                if stderr.contains("no note found for object") =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Read the body of the note attached to the seed's target OID
    /// under `notes_ref`. Bundles the seed-to-target-OID derivation
    /// (`git hash-object`) with the absent-classifying read, so a
    /// caller that holds the seed (and not the target OID) gets the
    /// same `Option<Vec<u8>>` shape [`Self::read_note_if_present`]
    /// returns without having to re-implement the hashing step.
    ///
    /// Sibling to [`Self::write_note_if_absent`]: the writer hashes
    /// the same seed bytes to pick the attach OID, so a reader that
    /// hashes those bytes again recovers the same OID and locates
    /// the writer's note. Determinism of `git hash-object` is the
    /// load-bearing property — content-addressed storage means
    /// no separate registry is needed to map seeds to targets.
    pub fn read_note_at_seed(
        &self,
        notes_ref: &NotesRef,
        seed: &[u8],
    ) -> Result<Option<Vec<u8>>, NotesRepoError> {
        // `HashWrite::Dry`: probing for an undecided plan must not
        // pollute the repo with an unreachable seed blob, and must
        // not fail if the repo is read-only. The OID is identical
        // either way; only the persistence side effect differs.
        let target_oid = hash_object_stdin(
            &self.canonical_path,
            seed,
            &self.inherited_env,
            HashWrite::Dry,
        )?;
        self.read_note_if_present(notes_ref, &target_oid)
    }

    /// Enumerate every ref whose full name starts with `prefix`,
    /// in git's lexicographic `for-each-ref` order.
    ///
    /// Used by reader-side helpers — `bailiff plan list` walks every
    /// plan-id under `refs/notes/bailiff/v1/plans/` this way. The
    /// caller passes the trailing slash explicitly: `for-each-ref`
    /// matches its argument as a literal path prefix when no glob
    /// chars are present, so `refs/notes/foo/` matches only refs
    /// inside that directory, not a sibling named `refs/notes/foo2`.
    ///
    /// An empty repo or a prefix that matches no refs returns
    /// `Ok(vec![])` — neither is an error. If git emits a refname
    /// our [`NotesRef`] validator refuses (the operator-corruption
    /// case: someone planted a malformed loose ref by hand), the
    /// helper surfaces it as `ForEachRefRefnameInvalid` rather than
    /// silently dropping the row, so callers cannot conflate
    /// "corrupted ref namespace" with "nothing here yet".
    pub fn list_refs_under_prefix(&self, prefix: &str) -> Result<Vec<NotesRef>, NotesRepoError> {
        let (stdout, stderr) = run_git_capturing_stderr(
            &self.canonical_path,
            ["for-each-ref", "--format=%(refname)", prefix],
            None,
            CaptureOutput::Capture,
            &self.inherited_env,
            // Read-only: nothing to double-apply.
            OnBornDead::Retry,
        )?;
        // `git for-each-ref --format=%(refname)` drops a row from
        // stdout (no `<missing>` placeholder) while writing a
        // warning to stderr and exiting 0 whenever it can't
        // enumerate a ref. The known shapes today are:
        //
        //   - `warning: ignoring ref with broken name <name>`
        //     — refname fails check-ref-format (e.g. ASCII
        //     whitespace, control char, `..` traversal).
        //   - `warning: ignoring broken ref <name>`
        //     — refname is fine but the ref's contents won't
        //     parse as a git object name.
        //
        // Without inspecting stderr the helper would return the
        // surviving rows and silently mask the broken one — which
        // is exactly the corruption-to-missing-row data loss this
        // primitive must surface. `for-each-ref` is documented as
        // silent on success, so we treat any non-empty stderr as
        // a corruption signal uniformly. That way today's known
        // shapes and any future-version shape both surface as the
        // same `ForEachRefStderr` error rather than silently
        // regressing on the property.
        let stderr_text = String::from_utf8_lossy(&stderr);
        let stderr_trimmed = stderr_text.trim();
        if !stderr_trimmed.is_empty() {
            return Err(NotesRepoError::ForEachRefStderr {
                stderr: stderr_trimmed.to_string(),
            });
        }
        let text = String::from_utf8(stdout)
            .map_err(|source| NotesRepoError::ForEachRefNonUtf8 { source })?;
        let mut refs = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let nref = NotesRef::try_new(line).map_err(|source| {
                NotesRepoError::ForEachRefRefnameInvalid {
                    raw: line.to_string(),
                    source,
                }
            })?;
            refs.push(nref);
        }
        Ok(refs)
    }
}

fn validate_bare_layout(path: &Path, env: &InheritedEnv) -> Result<(), NotesRepoError> {
    let head = path.join("HEAD");
    if !head.is_file() {
        return Err(NotesRepoError::MissingHead {
            path: path.to_path_buf(),
        });
    }
    let objects = path.join("objects");
    if !is_dir(&objects) {
        return Err(NotesRepoError::MissingObjectsDir { path: objects });
    }
    let refs = path.join("refs");
    if !is_dir(&refs) {
        return Err(NotesRepoError::MissingRefsDir { path: refs });
    }
    // `commondir` at the top level of a worktree points at the shared
    // dir of the parent repo; in a healthy standalone bare repo it
    // does not exist. `symlink_metadata` (lstat) detects the file
    // without following a symlink so a worktree pointing into the
    // repo cannot smuggle itself in as a bare layout.
    let commondir = path.join("commondir");
    match std::fs::symlink_metadata(&commondir) {
        Ok(_) => {
            return Err(NotesRepoError::Worktree { path: commondir });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(NotesRepoError::Io {
                path: commondir,
                source,
            });
        }
    }
    match git_config_get_bool(path, "core.bare", env)? {
        Some(true) => {}
        other => return Err(NotesRepoError::NotBare { value: other }),
    }
    if let Some(fmt) = git_config_get(path, "extensions.objectformat", env)?
        && fmt != "sha1"
    {
        return Err(NotesRepoError::UnsupportedObjectFormat { value: fmt });
    }
    Ok(())
}

fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum CaptureOutput {
    Discard,
    Capture,
}

/// Build a `Command` that runs `git` against `repo` with all host
/// configuration neutralised.
///
/// `env_clear` strips every inherited env var — `GIT_DIR`,
/// `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_DEFAULT_HASH`, and
/// the config-source overrides — so a hostile or just unusual parent
/// can never redirect or reconfigure the child. We then re-apply the
/// shared hardened recipe (`writ_core::git_env`) plus `PATH` so the
/// git binary itself remains discoverable.
///
/// `--git-dir=<repo>` is load-bearing alongside the env scrub:
/// implicit `-C <bare-repo>` discovery fails on hosts hardened
/// with `safe.bareRepository=explicit`, so we point git at the
/// repo by absolute path and never rely on directory walking.
/// This also makes `git init` write to exactly `<repo>` regardless
/// of how the operator's defaults would otherwise steer it.
fn prepare_git_command(repo: &Path, env: &InheritedEnv) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = env.path.as_ref() {
        command.env("PATH", path);
    }
    // Via the shared applier, not the constant: the recipe includes a *removal*
    // (`GIT_CONFIG`, which `git config` honours as `--file`) that a name/value
    // loop cannot express. `env_clear` above already covers it, but this module
    // runs `git config --local --get` to validate the repo, so the belt and
    // braces are cheap and the applier keeps the recipe whole in one place.
    writ_core::git_env::apply_clean_git_config(&mut command);
    let mut git_dir_arg = OsString::from("--git-dir=");
    git_dir_arg.push(repo);
    command.arg(git_dir_arg);
    command
}

fn run_git<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    on_born_dead: OnBornDead,
) -> Result<Vec<u8>, NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    run_git_capturing_stderr(repo, args, stdin_input, capture, env, on_born_dead)
        .map(|(stdout, _stderr)| stdout)
}

/// [`run_git`] under caller-chosen bounds.
///
/// One production caller — the repack in [`NotesRepo::compact_if_needed`], which
/// is the only command here whose legitimate cost grows with the repo's total
/// history. Everything else takes [`GitLimits::production`].
fn run_git_with_limits<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    limits: GitLimits,
    on_born_dead: OnBornDead,
) -> Result<Vec<u8>, NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    run_git_capturing_stderr_with_limits(
        repo,
        args,
        stdin_input,
        capture,
        env,
        limits,
        on_born_dead,
    )
    .map(|(stdout, _stderr)| stdout)
}

/// Variant of [`run_git`] that hands the caller both stdout and the
/// captured stderr on success. Most callers never need stderr on the
/// happy path — git prints to it only on warnings — but a few do.
/// `git for-each-ref` emits `warning: ignoring ref with broken name`
/// to stderr while exiting 0 when it encounters a loose ref whose
/// name fails `check-ref-format` (e.g. an operator hand-planted a
/// refname containing ASCII whitespace). That warning is a corruption
/// signal we have to surface; discarding stderr on success would let
/// it masquerade as "no rows here", so this helper exposes the bytes
/// and the caller decides.
///
/// Every invocation is supervised: stdin, stdout, and stderr are driven by one
/// non-blocking event loop, the whole call is bounded by
/// [`NOTES_GIT_TIMEOUT`], both captures are byte-capped, and the child's process
/// group is SIGKILLed on the way out so no helper it forked can outlive it or
/// hold a captured pipe open. Concurrent drains are what keep a child that
/// floods one stream from deadlocking against the other: `git for-each-ref` over
/// a heavily corrupted ref namespace emits one warning per broken ref and easily
/// exceeds the platform pipe-buffer size (64 KiB on Linux).
fn run_git_capturing_stderr<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    on_born_dead: OnBornDead,
) -> Result<(Vec<u8>, Vec<u8>), NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    run_git_capturing_stderr_with_limits(
        repo,
        args,
        stdin_input,
        capture,
        env,
        GitLimits::production(),
        on_born_dead,
    )
}

fn run_git_capturing_stderr_with_limits<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    limits: GitLimits,
    on_born_dead: OnBornDead,
) -> Result<(Vec<u8>, Vec<u8>), NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    let args: Vec<&str> = args.into_iter().collect();
    let mut command = prepare_git_command(repo, env);
    command.args(&args);
    let stdout_mode = match capture {
        CaptureOutput::Discard => StdoutMode::Discard,
        CaptureOutput::Capture => StdoutMode::Capture {
            byte_cap: limits.stdout_cap,
        },
    };

    let owned_args = || -> Vec<String> { args.iter().map(|s| (*s).to_string()).collect() };
    let (status, stdout, stderr) = supervised_git(
        &mut command,
        limits,
        stdin_input,
        stdout_mode,
        owned_args,
        on_born_dead,
    )?;
    if !status.success() {
        return Err(NotesRepoError::GitFailed {
            args: owned_args(),
            status,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    Ok((stdout, stderr))
}

/// Run one `git` child under the supervisor, re-running it while the child
/// provably ran nothing, and map the non-exit outcomes to this module's errors.
///
/// Both git call sites in this module go through here — including the
/// config-validation children on the `NotesRepo::open` path, where the born-dead
/// flake was first seen as `GitFailed { args: ["config"], status: signal 9 }`.
/// Returning the raw `ExitStatus` rather than judging it is what lets `git
/// config` keep its own reading of exit 1 ("key not set") without a second copy
/// of the retry.
fn supervised_git(
    command: &mut Command,
    limits: GitLimits,
    stdin_input: Option<&[u8]>,
    stdout_mode: StdoutMode,
    args: impl Fn() -> Vec<String>,
    on_born_dead: OnBornDead,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), NotesRepoError> {
    supervised_git_probed(
        command,
        limits,
        stdin_input,
        stdout_mode,
        args,
        on_born_dead,
        process_supervisor::pid_absent_when_probed,
    )
}

/// [`supervised_git`] with an injectable born-dead probe.
///
/// A genuinely born-dead child cannot be forged on demand — the kernel decides —
/// so a test that wants to drive the retry supplies its own probe. Explicit
/// argument rather than hidden indirection; [`supervised_git`] is the only
/// production caller.
fn supervised_git_probed(
    command: &mut Command,
    limits: GitLimits,
    stdin_input: Option<&[u8]>,
    stdout_mode: StdoutMode,
    args: impl Fn() -> Vec<String>,
    on_born_dead: OnBornDead,
    mut probe: impl FnMut(u32) -> bool,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), NotesRepoError> {
    for attempt in 0..BORN_DEAD_RETRY_ATTEMPTS {
        let outcome = process_supervisor::run_supervised_blocking_probed(
            command,
            limits.timeout,
            stdin_input,
            stdout_mode,
            StderrMode::Capture,
            &mut probe,
        )
        .map_err(|source| supervisor_error_to_notes_error(source, args()))?;

        return match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
                born_dead_signature,
            } => {
                if born_dead_signature {
                    match on_born_dead {
                        OnBornDead::Retry if attempt + 1 < BORN_DEAD_RETRY_ATTEMPTS => continue,
                        OnBornDead::Retry => {}
                        // We cannot tell whether this child took effect, so we
                        // decline to guess in either direction: not a silent
                        // replay, and not a success either.
                        OnBornDead::Fail => {
                            return Err(NotesRepoError::GitKilledBeforeCompletion { args: args() });
                        }
                    }
                }
                Ok((status, stdout, stderr))
            }
            SupervisedOutcome::TimedOut => Err(NotesRepoError::GitTimedOut {
                args: args(),
                timeout: limits.timeout,
            }),
            SupervisedOutcome::StdoutCapExceeded { cap } => {
                Err(NotesRepoError::GitStdoutCapExceeded { args: args(), cap })
            }
        };
    }
    unreachable!("the final attempt returns rather than continuing")
}

/// Map a supervisor failure onto this module's error type. The distinction the
/// callers care about is spawn-vs-everything-else: a refused spawn means git
/// never ran (so the repo is untouched), whereas the rest happened mid-flight.
fn supervisor_error_to_notes_error(err: SupervisorError, args: Vec<String>) -> NotesRepoError {
    match err {
        SupervisorError::Spawn(source) => NotesRepoError::GitSpawn { source },
        SupervisorError::Wait(source) => NotesRepoError::GitWait { source },
        // Preserve the pre-supervisor error shapes for these two, because callers
        // (and tests) distinguish them: a partial stdin delivery was
        // `GitStdinWrite`, and a failed output read was `GitWait`. Both mean the
        // command's data is incomplete, which must never look like success —
        // `hash-object --stdin` returning the id of a truncated body would
        // silently corrupt what the note attests.
        SupervisorError::StdinWrite { source, .. } => NotesRepoError::GitStdinWrite { source },
        SupervisorError::CaptureRead(source) => NotesRepoError::GitWait { source },
        other => NotesRepoError::GitSupervision {
            args,
            detail: other.to_string(),
        },
    }
}

fn git_config_get_bool(
    repo: &Path,
    key: &str,
    env: &InheritedEnv,
) -> Result<Option<bool>, NotesRepoError> {
    // `--local` is load-bearing: without it, `git config --get`
    // also reads `~/.gitconfig` and the system config, so a global
    // `core.bare = true` would let any directory with HEAD/objects/
    // refs pass validation, and a global `extensions.objectformat =
    // sha256` would reject a valid SHA-1 repo. The layout checks
    // are about the on-disk repo only.
    let output = run_git_config(repo, ["--local", "--bool", "--get", key], env)?;
    let Some(raw) = output else { return Ok(None) };
    let trimmed = raw.trim();
    match trimmed {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        other => Err(NotesRepoError::ConfigBoolUnparseable {
            key: key.to_string(),
            got: other.to_string(),
        }),
    }
}

fn git_config_get(
    repo: &Path,
    key: &str,
    env: &InheritedEnv,
) -> Result<Option<String>, NotesRepoError> {
    let output = run_git_config(repo, ["--local", "--get", key], env)?;
    Ok(output.map(|s| s.trim().to_string()))
}

fn run_git_config<'a>(
    repo: &Path,
    config_args: impl IntoIterator<Item = &'a str>,
    env: &InheritedEnv,
) -> Result<Option<String>, NotesRepoError> {
    // Supervised like every other git call here. This is the one command whose
    // *non-zero* exit is not necessarily an error (exit 1 means "key unset"), so
    // it cannot share `run_git_capturing_stderr`'s success check — but it gets
    // the identical timeout, caps, and process-group kill rather than its own
    // weaker discipline.
    let mut command = prepare_git_command(repo, env);
    command.arg("config");
    for arg in config_args {
        command.arg(arg);
    }
    let args = || vec!["config".to_string()];
    let limits = GitLimits::production();
    let (status, stdout, stderr) = supervised_git(
        &mut command,
        limits,
        None,
        StdoutMode::Capture {
            byte_cap: limits.stdout_cap,
        },
        args,
        // `config --get` only reads.
        OnBornDead::Retry,
    )?;

    if status.success() {
        let s =
            String::from_utf8(stdout).map_err(|source| NotesRepoError::ConfigNonUtf8 { source })?;
        Ok(Some(s))
    } else if status.code() == Some(1) {
        // Per `git config(1)`, exit code 1 means the key is not set.
        // Any other non-zero exit is an actual error.
        Ok(None)
    } else {
        Err(NotesRepoError::GitFailed {
            args: args(),
            status,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

/// Whether `hash_object_stdin` persists the resulting blob in the
/// object database (`git hash-object -w`) or just returns the OID
/// without writing it. The OID is identical either way; only the
/// side effect of materialising the blob differs.
///
/// Write callers need [`Self::Persist`] because the body blob the
/// note attaches to via `notes add -C <blob_oid>` must be
/// resolvable at the time of the attach. Read callers — which only
/// need the OID to look up the notes-tree entry — use [`Self::Dry`]
/// so probing for an absent note does not pollute the repo with
/// unreachable seed blobs, and so the operation works against a
/// read-only mirror.
#[derive(Copy, Clone, Eq, PartialEq)]
enum HashWrite {
    Persist,
    Dry,
}

fn hash_object_stdin(
    repo: &Path,
    bytes: &[u8],
    env: &InheritedEnv,
    write: HashWrite,
) -> Result<GitObjectId, NotesRepoError> {
    let args: &[&str] = match write {
        HashWrite::Persist => &["hash-object", "-w", "--stdin"],
        HashWrite::Dry => &["hash-object", "--stdin"],
    };
    let stdout = run_git(
        repo,
        args.iter().copied(),
        Some(bytes),
        CaptureOutput::Capture,
        env,
        // Content-addressed: `hash-object -w` on the same bytes writes the same
        // object at the same id, so a replay is idempotent by construction.
        OnBornDead::Retry,
    )?;
    let s =
        String::from_utf8(stdout).map_err(|source| NotesRepoError::HashObjectNonUtf8 { source })?;
    let trimmed = s.trim();
    GitObjectId::new(trimmed).map_err(|source| NotesRepoError::HashObjectParse {
        raw: trimmed.to_string(),
        source,
    })
}

/// Per-repo state that only a notes-write lock holder may read or write.
///
/// It lives *inside* the lock rather than beside it so that "consult the
/// compaction gate without holding the write lock" cannot be written down. The
/// alternative — a field on [`NotesRepo`] — would also have given each handle
/// its own gate, whereas the lock is deliberately keyed on the canonical path so
/// that two handles on one repo share it. State that gates a repo-wide operation
/// has to be shared the same way.
/// The compaction retry gate's deadline, in the repo it applies to.
///
/// A plain file of decimal milliseconds since the Unix epoch. In a bare repo
/// git ignores names it does not know, and the leading dot keeps it out of the
/// way of anything listing the layout.
const COMPACTION_RETRY_FILE: &str = ".writ-compaction-retry-after";

/// Holding this is the permission to touch the compaction retry gate.
///
/// The gate itself is *durable* — a file in the repo — because the process it
/// bounds is not always long-lived. It began as an `Instant` in this struct,
/// which was correct for `writd` and quietly useless for bailiff: bailiff is a
/// one-shot CLI, so the gate was born empty on every `plan submit`/`review`/
/// `implement`/`decide` and discarded at exit. A repo in the failing state then
/// paid a full `NOTES_GIT_TIMEOUT` twice per command, under a held lock, instead
/// of once an hour — precisely the unbounded degradation the gate exists to
/// prevent. (The same held for `writd` across a restart, which is why the
/// documented "one attempt per hour" was already stronger than the mechanism.)
///
/// It stays *behind* this struct, reachable only through `&self`/`&mut self`,
/// so consulting or moving the gate without holding the notes-write lock remains
/// unwriteable. That property is why the field became methods rather than a free
/// function taking a path.
#[derive(Debug)]
struct NotesRepoState;

impl NotesRepoState {
    /// How long the caller must wait, or `None` if the gate is open.
    ///
    /// Fails *open* on anything unreadable or unparseable: a corrupt gate that
    /// disabled compaction for ever would be a worse failure than one extra
    /// attempt, and there is nothing to distinguish a truncated write from a
    /// hostile one here anyway.
    ///
    /// A deadline further out than `COMPACTION_RETRY_BACKOFF` is treated as
    /// expired. Wall clocks move — that is the price of durability over
    /// `Instant` — and a backwards jump would otherwise strand the gate closed
    /// for however long the clock was wrong.
    fn compaction_retry_in(&self, repo: &Path, now: SystemTime) -> Option<Duration> {
        let raw = std::fs::read_to_string(repo.join(COMPACTION_RETRY_FILE)).ok()?;
        let millis: u64 = raw.trim().parse().ok()?;
        let until = SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(millis))?;
        let remaining = until.duration_since(now).ok()?;
        (remaining <= COMPACTION_RETRY_BACKOFF).then_some(remaining)
    }

    /// Close the gate for `COMPACTION_RETRY_BACKOFF` from `now`.
    ///
    /// Best-effort: a repo whose gate cannot be written is one where compaction
    /// will simply be attempted again, which is the behaviour writ had before
    /// the gate existed. Failing the caller's operation — whose note is already
    /// durable — over housekeeping bookkeeping would be the wrong trade.
    fn hold_off_compaction(&mut self, repo: &Path, now: SystemTime) {
        let until = now + COMPACTION_RETRY_BACKOFF;
        let Ok(since_epoch) = until.duration_since(SystemTime::UNIX_EPOCH) else {
            return;
        };
        if let Err(err) = std::fs::write(
            repo.join(COMPACTION_RETRY_FILE),
            since_epoch.as_millis().to_string(),
        ) {
            tracing::warn!(%err, "could not record the compaction retry gate");
        }
    }

    /// Open the gate. Absence is the open state, so removal is the whole job.
    fn allow_compaction(&mut self, repo: &Path) {
        match std::fs::remove_file(repo.join(COMPACTION_RETRY_FILE)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(%err, "could not clear the compaction retry gate"),
        }
    }
}

fn lock_notes_write(canonical_path: &Path) -> MutexGuard<'static, NotesRepoState> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, &'static Mutex<NotesRepoState>>>> =
        OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mutex_ref: &'static Mutex<NotesRepoState> = {
        let mut guard = registry
            .lock()
            .expect("notes-write registry mutex poisoned");
        if let Some(m) = guard.get(canonical_path) {
            m
        } else {
            // Leaking a `Box<Mutex<_>>` once per distinct repo
            // gives every handle a `'static` reference to share.
            // The number of distinct repos in a single process is
            // bounded by deployment shape (one per daemon today,
            // perhaps a handful in tests) so the leak is negligible.
            let leaked: &'static Mutex<NotesRepoState> =
                Box::leak(Box::new(Mutex::new(NotesRepoState)));
            guard.insert(canonical_path.to_path_buf(), leaked);
            leaked
        }
    };
    // A poisoned per-repo mutex means a previous note-write call
    // panicked while holding the lock — there is no recovery story
    // beyond letting the panic propagate, so unwrap rather than
    // silently re-acquiring a poisoned guard.
    mutex_ref
        .lock()
        .expect("per-repo notes-write mutex poisoned")
}

#[derive(Debug, thiserror::Error)]
pub enum NotesRepoError {
    #[error("cannot canonicalise repo path {path:?}: {source}")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot create repo directory {path:?}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("repo missing HEAD file at {path:?}")]
    MissingHead { path: PathBuf },
    #[error("repo missing objects directory at {path:?}")]
    MissingObjectsDir { path: PathBuf },
    #[error("repo missing refs directory at {path:?}")]
    MissingRefsDir { path: PathBuf },
    #[error("worktree marker {path:?} present; NotesRepo requires a standalone bare repo")]
    Worktree { path: PathBuf },
    #[error("repo has core.bare={value:?}, expected core.bare=true")]
    NotBare { value: Option<bool> },
    #[error("repo has extensions.objectformat={value:?}; NotesRepo only supports sha1")]
    UnsupportedObjectFormat { value: String },
    #[error("git config --bool --get {key} returned non-bool {got:?}")]
    ConfigBoolUnparseable { key: String, got: String },
    #[error("git config output is not valid UTF-8: {source}")]
    ConfigNonUtf8 { source: std::string::FromUtf8Error },
    #[error("git hash-object output is not valid UTF-8: {source}")]
    HashObjectNonUtf8 { source: std::string::FromUtf8Error },
    #[error("git count-objects output is not valid UTF-8: {source}")]
    CountObjectsNonUtf8 { source: std::string::FromUtf8Error },
    #[error("git count-objects -v output could not be read: {source}")]
    CountObjectsParse {
        #[source]
        source: compaction::CountObjectsParseError,
    },
    #[error("git hash-object produced unparseable OID {raw:?}: {source}")]
    HashObjectParse {
        raw: String,
        source: GitObjectIdError,
    },
    #[error("filesystem error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("note body must be non-empty")]
    EmptyBody,
    #[error("fetch refspec list must be non-empty")]
    EmptyRefspecs,
    #[error("fetch source path {path:?} is not valid UTF-8")]
    SourcePathNonUtf8 { path: PathBuf },
    #[error("git command could not be spawned: {source}")]
    GitSpawn { source: std::io::Error },
    #[error("git command stdin write failed: {source}")]
    GitStdinWrite { source: std::io::Error },
    #[error("git command wait/drain failed: {source}")]
    GitWait { source: std::io::Error },
    #[error("git {args:?} exited with {status}: {stderr}")]
    GitFailed {
        args: Vec<String>,
        status: ExitStatus,
        stderr: String,
    },
    #[error("git {args:?} did not finish within {timeout:?}; its process group was killed")]
    GitTimedOut {
        args: Vec<String>,
        timeout: Duration,
    },
    #[error(
        "git {args:?} was killed before it could report an outcome, and whether it took effect is unknown; not replaying it"
    )]
    GitKilledBeforeCompletion { args: Vec<String> },
    #[error(
        "git {args:?} wrote more than the {cap}-byte stdout capture cap; its process group was killed and the output discarded"
    )]
    GitStdoutCapExceeded { args: Vec<String>, cap: usize },
    #[error("git {args:?} could not be supervised: {detail}")]
    GitSupervision { args: Vec<String>, detail: String },
    #[error("git for-each-ref output is not valid UTF-8: {source}")]
    ForEachRefNonUtf8 { source: std::string::FromUtf8Error },
    #[error("git for-each-ref returned refname {raw:?} that fails validation: {source}")]
    ForEachRefRefnameInvalid { raw: String, source: NotesRefError },
    #[error("git for-each-ref wrote to stderr (corruption signal): {stderr}")]
    ForEachRefStderr { stderr: String },
}

pub mod compaction;

#[cfg(test)]
mod tests;
