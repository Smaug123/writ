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
//!
//! Host-config isolation: every child `git` runs under `env_clear`
//! plus the `clean_git` config recipe (`HOME=/dev/null`,
//! `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`,
//! `GIT_CONFIG_COUNT=0`), so neither an inherited `GIT_DIR` /
//! `GIT_DEFAULT_HASH` nor a host-wide `safe.bareRepository` /
//! `init.defaultObjectFormat` setting can subvert the owning
//! daemon's repo.
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

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use crate::clean_git::CLEAN_GIT_CONFIG_ENV;
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

/// Attempts allowed for a child that died before it ran anything (see
/// [`crate::process_supervisor::child_ran_nothing`]).
///
/// An attempt count is right here, where a deadline is right for a transient
/// spawn *refusal*: a refusal clears on the host's schedule, so we wait it out;
/// a born-dead child is a per-spawn lottery at roughly 1-in-2000, so what we
/// want is another ticket, not a wait. Three attempts put the residual odds past
/// 1-in-10^10.
const BORN_DEAD_RETRY_ATTEMPTS: usize = 3;

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
        // needs an author identity. The `clean_git` env recipe
        // we run under (HOME=/dev/null, GIT_CONFIG_GLOBAL=/dev/null,
        // GIT_CONFIG_NOSYSTEM=1) deliberately denies git access to
        // every config source except the repo's local file, so we
        // inject the identity via `-c` flags rather than rely on
        // operator gitconfig. The values are placeholders — the
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
        )?;
        Ok(())
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
/// `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_DEFAULT_HASH`,
/// `GIT_CONFIG_GLOBAL`, etc. — so a hostile or just unusual parent
/// can never redirect or reconfigure the child. We then re-add the
/// `clean_git` hardening recipe (`HOME=/dev/null`,
/// `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
/// `GIT_CONFIG_COUNT=0`) plus `PATH` so the git binary itself
/// remains discoverable.
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
    for (key, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(key, value);
    }
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
) -> Result<Vec<u8>, NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    run_git_capturing_stderr(repo, args, stdin_input, capture, env).map(|(stdout, _stderr)| stdout)
}

/// [`run_git`] under caller-chosen bounds. Only tests need anything other than
/// [`GitLimits::production`].
#[cfg(test)]
fn run_git_with_limits<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    limits: GitLimits,
) -> Result<Vec<u8>, NotesRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    run_git_capturing_stderr_with_limits(repo, args, stdin_input, capture, env, limits)
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
    )
}

fn run_git_capturing_stderr_with_limits<'a, I>(
    repo: &Path,
    args: I,
    stdin_input: Option<&[u8]>,
    capture: CaptureOutput,
    env: &InheritedEnv,
    limits: GitLimits,
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
    let (status, stdout, stderr) =
        supervised_git(&mut command, limits, stdin_input, stdout_mode, owned_args)?;
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
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), NotesRepoError> {
    supervised_git_probed(
        command,
        limits,
        stdin_input,
        stdout_mode,
        args,
        process_supervisor::child_vanished_before_running,
    )
}

/// [`supervised_git`] with an injectable proof-of-life probe.
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
    mut probe: impl FnMut(u32) -> bool,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), NotesRepoError> {
    // The supervisor takes a proof-of-life probe between spawn and reap and
    // reports it as `ran_nothing`; see `process_supervisor::child_ran_nothing`
    // for why re-running is safe even for a *mutating* command like `notes add`
    // (the claim is not that the command may be repeated, but that this child had
    // no effect to repeat).
    for attempt in 0..BORN_DEAD_RETRY_ATTEMPTS {
        let outcome = process_supervisor::run_supervised_blocking_probed(
            command,
            limits.timeout,
            stdin_input,
            stdout_mode,
            StderrMode::Capture,
            |pid| probe(pid),
        )
        .map_err(|source| supervisor_error_to_notes_error(source, args()))?;

        return match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
                ran_nothing,
            } => {
                if ran_nothing && attempt + 1 < BORN_DEAD_RETRY_ATTEMPTS {
                    continue;
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
    )?;
    let s =
        String::from_utf8(stdout).map_err(|source| NotesRepoError::HashObjectNonUtf8 { source })?;
    let trimmed = s.trim();
    GitObjectId::new(trimmed).map_err(|source| NotesRepoError::HashObjectParse {
        raw: trimmed.to_string(),
        source,
    })
}

fn lock_notes_write(canonical_path: &Path) -> MutexGuard<'static, ()> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mutex_ref: &'static Mutex<()> = {
        let mut guard = registry
            .lock()
            .expect("notes-write registry mutex poisoned");
        if let Some(m) = guard.get(canonical_path) {
            m
        } else {
            // Leaking a `Box<Mutex<()>>` once per distinct repo
            // gives every handle a `'static` reference to share.
            // The number of distinct repos in a single process is
            // bounded by deployment shape (one per daemon today,
            // perhaps a handful in tests) so the leak is negligible.
            let leaked: &'static Mutex<()> = Box::leak(Box::new(Mutex::new(())));
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

#[cfg(test)]
mod tests;
