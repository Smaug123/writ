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

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::clean_git::CLEAN_GIT_CONFIG_ENV;
use crate::core::NotesRef;
use crate::vm_git::{GitObjectId, GitObjectIdError};

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
        let target_oid = hash_object_stdin(&self.canonical_path, seed, &self.inherited_env)?;
        // Write the body as a blob first and reference it via `-C
        // <oid>`. `git notes add -F file` runs the body through
        // `stripspace` (strip trailing whitespace per line, collapse
        // blank lines) which corrupts arbitrary bytes — the envelope
        // is binary in general, so we have to bypass stripspace.
        // `-C <existing_blob_oid>` reuses the object verbatim and is
        // the documented escape hatch.
        let body_oid = hash_object_stdin(&self.canonical_path, body, &self.inherited_env)?;
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
        let target_oid = hash_object_stdin(&self.canonical_path, seed, &self.inherited_env)?;
        if self.read_note_if_present(notes_ref, &target_oid)?.is_some() {
            return Ok(WriteOutcome::AlreadyPresent(target_oid));
        }
        let body_oid = hash_object_stdin(&self.canonical_path, body, &self.inherited_env)?;
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
            args.into_iter(),
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
        let target_oid = hash_object_stdin(&self.canonical_path, seed, &self.inherited_env)?;
        self.read_note_if_present(notes_ref, &target_oid)
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
    let args: Vec<&str> = args.into_iter().collect();
    let mut command = prepare_git_command(repo, env);
    command.args(&args);
    command.stdin(if stdin_input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(match capture {
        CaptureOutput::Discard => Stdio::null(),
        CaptureOutput::Capture => Stdio::piped(),
    });
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|source| NotesRepoError::GitSpawn { source })?;

    if let Some(bytes) = stdin_input {
        let mut stdin = child
            .stdin
            .take()
            .expect("stdin was configured as Stdio::piped()");
        stdin
            .write_all(bytes)
            .map_err(|source| NotesRepoError::GitStdinWrite { source })?;
        drop(stdin);
    }

    let mut stdout_bytes = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_end(&mut stdout_bytes)
            .map_err(|source| NotesRepoError::GitStdoutRead { source })?;
    }
    let mut stderr_bytes = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut stderr_bytes);
    }

    let status = child
        .wait()
        .map_err(|source| NotesRepoError::GitWait { source })?;
    if !status.success() {
        return Err(NotesRepoError::GitFailed {
            args: args.iter().map(|s| (*s).to_string()).collect(),
            status,
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        });
    }
    Ok(stdout_bytes)
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
    let mut command = prepare_git_command(repo, env);
    command.arg("config");
    for arg in config_args {
        command.arg(arg);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|source| NotesRepoError::GitSpawn { source })?;
    if output.status.success() {
        let s = String::from_utf8(output.stdout)
            .map_err(|source| NotesRepoError::ConfigNonUtf8 { source })?;
        Ok(Some(s))
    } else if output.status.code() == Some(1) {
        // Per `git config(1)`, exit code 1 means the key is not set.
        // Any other non-zero exit is an actual error.
        Ok(None)
    } else {
        Err(NotesRepoError::GitFailed {
            args: vec!["config".to_string()],
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn hash_object_stdin(
    repo: &Path,
    bytes: &[u8],
    env: &InheritedEnv,
) -> Result<GitObjectId, NotesRepoError> {
    let stdout = run_git(
        repo,
        ["hash-object", "-w", "--stdin"].iter().copied(),
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
    #[error("git command stdout read failed: {source}")]
    GitStdoutRead { source: std::io::Error },
    #[error("git command wait failed: {source}")]
    GitWait { source: std::io::Error },
    #[error("git {args:?} exited with {status}: {stderr}")]
    GitFailed {
        args: Vec<String>,
        status: ExitStatus,
        stderr: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use tempfile::TempDir;

    fn notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    #[test]
    fn init_or_open_creates_a_bare_repo() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bailiff-repo");
        let repo = NotesRepo::init_or_open(&path).unwrap();
        assert!(path.join("HEAD").is_file(), "HEAD should exist after init");
        assert!(path.join("objects").is_dir());
        assert!(path.join("refs").is_dir());
        // Canonicalised path resolves through any tmp symlinks.
        assert_eq!(repo.path(), path.canonicalize().unwrap());
    }

    #[test]
    fn init_or_open_is_idempotent_across_calls() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bailiff-repo");
        let a = NotesRepo::init_or_open(&path).unwrap();
        let b = NotesRepo::init_or_open(&path).unwrap();
        assert_eq!(a.path(), b.path());
    }

    #[test]
    fn open_rejects_a_plain_directory() {
        let tmp = TempDir::new().unwrap();
        let err = NotesRepo::open(tmp.path()).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_non_bare_repo() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("non-bare");
        // `git init` (no --bare) produces a working-directory repo
        // whose top-level layout includes `.git/` rather than the
        // bare layout. The validation must reject pointing at either
        // the worktree root or the inner `.git` dir.
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let err = NotesRepo::open(&path).unwrap_err();
        // Top-level: no HEAD file at the worktree root.
        assert!(
            matches!(err, NotesRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
        // Inner `.git`: HEAD exists but core.bare=false.
        let err_inner = NotesRepo::open(path.join(".git")).unwrap_err();
        assert!(
            matches!(err_inner, NotesRepoError::NotBare { value: Some(false) }),
            "got: {err_inner:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_head() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_file(repo.path().join("HEAD")).unwrap();
        let err = NotesRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_objects() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_dir_all(repo.path().join("objects")).unwrap();
        let err = NotesRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::MissingObjectsDir { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_refs() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_dir_all(repo.path().join("refs")).unwrap();
        let err = NotesRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::MissingRefsDir { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_with_commondir_marker() {
        // Worktrees of another repo have a `commondir` file at their
        // top level pointing at the parent's git dir; a NotesRepo
        // bare repo never has one. Plant the marker and confirm we
        // reject.
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::write(repo.path().join("commondir"), "../some/other/.git\n").unwrap();
        let err = NotesRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::Worktree { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_with_sha256_object_format() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("sha256-repo");
        let status = Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg("--object-format=sha256")
            .arg("--quiet")
            .arg(&path)
            .status();
        match status {
            Ok(s) if s.success() => {}
            // Older Git builds without sha256 support can't run this
            // case; skip rather than fail. We don't need to test on
            // every Git version, just confirm the gate exists on Git
            // versions that *can* produce a sha256 repo.
            _ => return,
        }
        let err = NotesRepo::open(&path).unwrap_err();
        assert!(
            matches!(
                err,
                NotesRepoError::UnsupportedObjectFormat { ref value } if value == "sha256"
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn write_note_round_trips_through_read_note() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let body = b"the signed envelope bytes go here";
        let seed = b"run-id-1";
        let target = repo.write_note(&nref, seed, body).unwrap();
        let read_back = repo.read_note(&nref, &target).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn write_note_keys_distinct_seeds_to_distinct_oids() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let a = repo.write_note(&nref, b"run-a", b"body A").unwrap();
        let b = repo.write_note(&nref, b"run-b", b"body B").unwrap();
        assert_ne!(a, b);
        assert_eq!(repo.read_note(&nref, &a).unwrap(), b"body A");
        assert_eq!(repo.read_note(&nref, &b).unwrap(), b"body B");
    }

    #[test]
    fn write_note_with_same_seed_is_content_addressed() {
        // Same seed bytes ⇒ same blob OID, so the second note-add
        // tries to attach to an existing target. Without `-f`, `git
        // notes add` refuses to overwrite an existing note, which
        // surfaces as our `GitFailed` variant — the property that
        // makes accidental duplicate writes loud rather than silent.
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let first = repo.write_note(&nref, b"seed", b"first body").unwrap();
        let err = repo.write_note(&nref, b"seed", b"second body").unwrap_err();
        match err {
            NotesRepoError::GitFailed { ref args, .. } => {
                assert!(
                    args.iter().any(|a| a == "notes"),
                    "expected the notes command to be the failure point, got: {args:?}"
                );
            }
            other => panic!("expected GitFailed from notes add, got: {other:?}"),
        }
        // The first note is still there.
        assert_eq!(repo.read_note(&nref, &first).unwrap(), b"first body");
    }

    #[test]
    fn read_note_errors_on_missing_target() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        // Write *something* under the ref so the ref exists, but ask
        // for a different target — exercises "ref present, no note
        // at this oid" rather than "ref missing entirely".
        let _ = repo.write_note(&nref, b"seed", b"body").unwrap();
        let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
        let err = repo.read_note(&nref, &absent).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::GitFailed { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn notes_under_distinct_refs_do_not_collide() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let ref_a = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let ref_b = NotesRef::try_new("refs/notes/bailiff/v1/plans").unwrap();
        let target_a = repo.write_note(&ref_a, b"seed", b"under A").unwrap();
        let target_b = repo.write_note(&ref_b, b"seed", b"under B").unwrap();
        // Same seed ⇒ same OID; the note bodies live under different refs.
        assert_eq!(target_a, target_b);
        assert_eq!(repo.read_note(&ref_a, &target_a).unwrap(), b"under A");
        assert_eq!(repo.read_note(&ref_b, &target_b).unwrap(), b"under B");
    }

    #[test]
    fn write_note_preserves_trailing_newline_in_body() {
        // `git notes show` appends a single trailing newline; the
        // read path strips exactly one. Bodies that end with one
        // newline must come back identical (not double-stripped).
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let body = b"body ending in a newline\n";
        let target = repo.write_note(&nref, b"seed", body).unwrap();
        assert_eq!(repo.read_note(&nref, &target).unwrap(), body);
    }

    #[test]
    fn write_note_rejects_empty_body() {
        // `git notes add -C <empty-blob-oid>` succeeds without
        // attaching a note, so the helper must reject empty bodies
        // before they reach git rather than returning a target OID
        // that read_note cannot resolve.
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let err = repo.write_note(&nref, b"seed", b"").unwrap_err();
        assert!(matches!(err, NotesRepoError::EmptyBody), "got: {err:?}");
    }

    #[test]
    fn init_or_open_does_not_mutate_existing_non_bare_repo() {
        // Pointing `init_or_open` at the `.git` directory of a real
        // worktree must not run `git init --bare` against it: that
        // would flip core.bare and silently break the worktree. The
        // expected behaviour is to validate-only and surface the
        // mismatch as an open error.
        let tmp = TempDir::new().unwrap();
        let worktree = tmp.path().join("wt");
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&worktree)
            .status()
            .unwrap();
        assert!(status.success());
        let git_dir = worktree.join(".git");
        // Capture HEAD + config before the call so we can confirm
        // init was not run against the existing repo.
        let head_before = fs::read(git_dir.join("HEAD")).unwrap();
        let config_before = fs::read(git_dir.join("config")).unwrap();
        let err = NotesRepo::init_or_open(&git_dir).unwrap_err();
        assert!(
            matches!(err, NotesRepoError::NotBare { value: Some(false) }),
            "got: {err:?}"
        );
        assert_eq!(fs::read(git_dir.join("HEAD")).unwrap(), head_before);
        assert_eq!(fs::read(git_dir.join("config")).unwrap(), config_before);
    }

    #[test]
    fn fetch_from_remote_copies_notes_between_repos() {
        // The writ→bailiff handoff: writ writes a note in its bare
        // repo, bailiff fetches the notes ref from writ's repo, and
        // the resulting target OID is readable on bailiff's side
        // under the same notes ref. The fetched body must be
        // byte-identical to the source body.
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let nref = notes_ref();
        let body = b"signed envelope bytes";
        let target = source_repo.write_note(&nref, b"run-id", body).unwrap();

        dest_repo
            .fetch_from_remote(
                source_repo.path(),
                &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
            )
            .unwrap();

        let read_back = dest_repo.read_note(&nref, &target).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn fetch_from_remote_round_trips_binary_body() {
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let nref = notes_ref();
        let body: Vec<u8> = (0u8..=255).collect();
        let target = source_repo.write_note(&nref, b"run-id", &body).unwrap();

        dest_repo
            .fetch_from_remote(
                source_repo.path(),
                &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
            )
            .unwrap();

        assert_eq!(dest_repo.read_note(&nref, &target).unwrap(), body);
    }

    #[test]
    fn fetch_from_remote_is_idempotent_under_repeated_calls() {
        // A second fetch with the same refspec is a no-op because
        // the dest refs are already current. The force flag (`+`)
        // makes the operation safe to repeat even if the source
        // moves; here we just confirm the second call doesn't error.
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let nref = notes_ref();
        let body = b"envelope";
        let target = source_repo.write_note(&nref, b"seed", body).unwrap();
        let refspecs = &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"];
        dest_repo
            .fetch_from_remote(source_repo.path(), refspecs)
            .unwrap();
        dest_repo
            .fetch_from_remote(source_repo.path(), refspecs)
            .unwrap();
        assert_eq!(dest_repo.read_note(&nref, &target).unwrap(), body);
    }

    #[test]
    fn fetch_from_remote_picks_up_new_notes_on_subsequent_call() {
        // Fetching only mirrors what's in the source at the time of
        // the call; a later writ-side write must surface on bailiff's
        // side after another fetch. This is the load-bearing
        // operational property: bailiff polls writ.
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let nref = notes_ref();
        let refspecs = &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"];

        let first = source_repo
            .write_note(&nref, b"run-1", b"first envelope")
            .unwrap();
        dest_repo
            .fetch_from_remote(source_repo.path(), refspecs)
            .unwrap();
        assert_eq!(
            dest_repo.read_note(&nref, &first).unwrap(),
            b"first envelope"
        );

        let second = source_repo
            .write_note(&nref, b"run-2", b"second envelope")
            .unwrap();
        // The second note is not yet on bailiff's side.
        assert!(dest_repo.read_note(&nref, &second).is_err());
        dest_repo
            .fetch_from_remote(source_repo.path(), refspecs)
            .unwrap();
        assert_eq!(
            dest_repo.read_note(&nref, &second).unwrap(),
            b"second envelope"
        );
    }

    #[test]
    fn fetch_from_remote_errors_on_missing_source() {
        // Pointing at a nonexistent path must surface as a GitFailed
        // error, not a panic or silent success. This is the
        // operator-misconfiguration case (wrong path in bailiff
        // config) and it must be loud.
        let tmp = TempDir::new().unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bogus = tmp.path().join("does-not-exist");
        let err = dest_repo
            .fetch_from_remote(&bogus, &["+refs/notes/*:refs/notes/*"])
            .unwrap_err();
        assert!(
            matches!(err, NotesRepoError::GitFailed { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn fetch_from_remote_rejects_empty_refspecs() {
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let err = dest_repo
            .fetch_from_remote(source_repo.path(), &[])
            .unwrap_err();
        assert!(matches!(err, NotesRepoError::EmptyRefspecs), "got: {err:?}");
    }

    #[test]
    fn fetch_from_remote_with_no_matching_refs_succeeds() {
        // The source repo is empty (no notes refs at all). A glob
        // refspec produces no matches but git still treats that as
        // success — we just want a green return, not a typed error.
        let tmp = TempDir::new().unwrap();
        let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        dest_repo
            .fetch_from_remote(
                source_repo.path(),
                &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
            )
            .unwrap();
    }

    #[test]
    fn write_note_handles_binary_body() {
        // The envelope bytes will not be UTF-8 in general (stdout/stderr
        // are arbitrary bytes). The pipe-to-stdin path must not
        // corrupt non-UTF-8 input.
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let body: Vec<u8> = (0u8..=255).collect();
        let target = repo.write_note(&nref, b"seed", &body).unwrap();
        assert_eq!(repo.read_note(&nref, &target).unwrap(), body);
    }

    // The host-config-hardening tests below inspect the `Command`
    // produced by `prepare_git_command` rather than mutating real
    // process env. The properties they pin down:
    //
    // * The clean-recipe env (`HOME=/dev/null`,
    //   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`,
    //   `GIT_CONFIG_COUNT=0`) is unconditionally set on the child —
    //   so a host-wide `GIT_CONFIG_GLOBAL` pointing at a poisoned
    //   file, `init.defaultObjectFormat = sha256` in `~/.gitconfig`,
    //   `safe.bareRepository = explicit`, etc. cannot reach git.
    // * `PATH` flows from the supplied `InheritedEnv`, not from a
    //   hidden `std::env::var_os` call — so production passes the
    //   captured parent env explicitly and tests can substitute.
    // * `--git-dir=<repo>` is the first arg — so an inherited
    //   `GIT_DIR` cannot redirect us, and discovery (which a host
    //   with `safe.bareRepository=explicit` disables) is never
    //   consulted.
    //
    // Trusting git's documented semantics for `--local`,
    // `--git-dir`, and `--object-format=sha1` is the load-bearing
    // step; verifying that we *invoke* git with those flags is
    // what these tests cover.
    fn synthetic_env(path: &str) -> InheritedEnv {
        InheritedEnv {
            path: Some(OsString::from(path)),
        }
    }

    fn envs_of(cmd: &Command) -> HashMap<OsString, Option<OsString>> {
        cmd.get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
            .collect()
    }

    #[test]
    fn prepare_git_command_pins_clean_recipe_and_inherits_only_path() {
        let env = synthetic_env("/usr/bin:/bin");
        let cmd = prepare_git_command(Path::new("/some/repo"), &env);
        let envs = envs_of(&cmd);
        assert_eq!(
            envs.get(OsStr::new("PATH")),
            Some(&Some(OsString::from("/usr/bin:/bin"))),
            "PATH must flow from InheritedEnv, not std::env"
        );
        assert_eq!(
            envs.get(OsStr::new("HOME")),
            Some(&Some(OsString::from("/dev/null")))
        );
        assert_eq!(
            envs.get(OsStr::new("GIT_CONFIG_GLOBAL")),
            Some(&Some(OsString::from("/dev/null"))),
            "child must see GIT_CONFIG_GLOBAL=/dev/null so a host-wide \
             poisoned global config cannot reach git"
        );
        assert_eq!(
            envs.get(OsStr::new("GIT_CONFIG_NOSYSTEM")),
            Some(&Some(OsString::from("1")))
        );
        assert_eq!(
            envs.get(OsStr::new("GIT_CONFIG_COUNT")),
            Some(&Some(OsString::from("0")))
        );
    }

    #[test]
    fn prepare_git_command_passes_repo_via_git_dir_arg() {
        // `--git-dir=<repo>` sidesteps both `GIT_DIR` env override
        // and `safe.bareRepository=explicit` discovery hardening.
        let env = synthetic_env("/usr/bin");
        let cmd = prepare_git_command(Path::new("/some/repo"), &env);
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert!(
            !args.is_empty(),
            "prepare_git_command must add at least --git-dir"
        );
        assert_eq!(args[0], OsStr::new("--git-dir=/some/repo"));
    }

    #[test]
    fn prepare_git_command_omits_path_when_inherited_env_lacks_it() {
        // If the captured parent env has no PATH, the child should
        // get no PATH either — not a stale value from the wider
        // process. The other clean-recipe entries remain.
        let env = InheritedEnv { path: None };
        let cmd = prepare_git_command(Path::new("/some/repo"), &env);
        let envs = envs_of(&cmd);
        assert!(
            !envs.contains_key(OsStr::new("PATH")),
            "PATH must be absent when InheritedEnv carries None; got: {envs:?}"
        );
        assert_eq!(
            envs.get(OsStr::new("HOME")),
            Some(&Some(OsString::from("/dev/null")))
        );
    }

    // --- read_note_if_present / write_note_if_absent ----------------------

    /// When the notes ref does not exist at all (fresh repo, never
    /// written), `read_note_if_present` folds the failure into
    /// `Ok(None)` instead of surfacing it as `NotesRepoError`.
    #[test]
    fn read_note_if_present_returns_none_when_ref_does_not_exist() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
        let res = repo.read_note_if_present(&nref, &absent).unwrap();
        assert!(res.is_none(), "expected None on missing ref, got: {res:?}");
    }

    /// When the notes ref exists but has no annotation at the target,
    /// the result is also `Ok(None)`. Exercises the "ref present, no
    /// note at this oid" branch of the absent-classifier.
    #[test]
    fn read_note_if_present_returns_none_when_ref_has_no_note_at_target() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        // Create the ref with one note keyed on a different seed.
        let _ = repo.write_note(&nref, b"some-other-seed", b"body").unwrap();
        let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
        let res = repo.read_note_if_present(&nref, &absent).unwrap();
        assert!(res.is_none(), "expected None on missing note, got: {res:?}");
    }

    /// When a note is present, `read_note_if_present` returns the
    /// same bytes [`NotesRepo::read_note`] would (i.e. `Some(body)`),
    /// confirming the absent-classifier doesn't accidentally swallow
    /// the present case.
    #[test]
    fn read_note_if_present_returns_some_body_when_note_exists() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let target = repo.write_note(&nref, b"seed-A", b"hello").unwrap();
        let body = repo.read_note_if_present(&nref, &target).unwrap();
        assert_eq!(body.as_deref(), Some(b"hello".as_slice()));
    }

    /// First call writes, returning `Written(target)`; the same
    /// target is reachable via `read_note_if_present` afterwards.
    /// Pins the success path before exercising the idempotent
    /// branch.
    #[test]
    fn write_note_if_absent_writes_on_first_call() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let outcome = repo
            .write_note_if_absent(&nref, b"seed-A", b"body-A")
            .unwrap();
        match outcome {
            WriteOutcome::Written(target) => {
                let read_back = repo.read_note_if_present(&nref, &target).unwrap();
                assert_eq!(read_back.as_deref(), Some(b"body-A".as_slice()));
            }
            WriteOutcome::AlreadyPresent(target) => {
                panic!("first call should write, got AlreadyPresent({target})");
            }
        }
    }

    /// Second call against the same seed returns `AlreadyPresent`
    /// without touching the existing body. Body bytes from the
    /// second call's `body` argument are deliberately different so
    /// any silent overwrite would surface.
    #[test]
    fn write_note_if_absent_is_idempotent_on_repeat_call() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let first = repo
            .write_note_if_absent(&nref, b"seed-A", b"first body")
            .unwrap();
        let target = match first {
            WriteOutcome::Written(oid) => oid,
            WriteOutcome::AlreadyPresent(oid) => panic!("first call should write, got {oid}"),
        };
        let second = repo
            .write_note_if_absent(&nref, b"seed-A", b"second body")
            .unwrap();
        match second {
            WriteOutcome::AlreadyPresent(oid) => assert_eq!(oid, target),
            WriteOutcome::Written(oid) => panic!("second call should be no-op, got {oid}"),
        }
        // The first body must still be the one attached.
        let body = repo.read_note(&nref, &target).unwrap();
        assert_eq!(body, b"first body");
    }

    /// Different seeds under the same ref each get their own
    /// `Written` outcome; the existence check is keyed on the target
    /// OID, not on "is there any note under this ref?".
    #[test]
    fn write_note_if_absent_distinguishes_seeds() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let a = repo
            .write_note_if_absent(&nref, b"seed-A", b"body-A")
            .unwrap();
        let b = repo
            .write_note_if_absent(&nref, b"seed-B", b"body-B")
            .unwrap();
        let target_a = match a {
            WriteOutcome::Written(o) => o,
            WriteOutcome::AlreadyPresent(o) => panic!("seed-A should write, got {o}"),
        };
        let target_b = match b {
            WriteOutcome::Written(o) => o,
            WriteOutcome::AlreadyPresent(o) => panic!("seed-B should write, got {o}"),
        };
        assert_ne!(
            target_a, target_b,
            "distinct seeds must hash to distinct targets"
        );
        assert_eq!(repo.read_note(&nref, &target_a).unwrap(), b"body-A");
        assert_eq!(repo.read_note(&nref, &target_b).unwrap(), b"body-B");
    }

    /// `write_note_if_absent` rejects empty bodies for the same
    /// reason `write_note` does: `git notes add -C <empty-blob-oid>`
    /// succeeds without attaching a note, so an empty body would
    /// silently fail to write and the next idempotent probe would
    /// see "no note" and write again forever.
    #[test]
    fn write_note_if_absent_rejects_empty_body() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let err = repo
            .write_note_if_absent(&nref, b"seed-A", b"")
            .unwrap_err();
        assert!(matches!(err, NotesRepoError::EmptyBody), "got: {err:?}");
    }

    /// Round-trip pin: writing under a seed and reading back via the
    /// same seed recovers the body byte-for-byte. The writer hashes
    /// the seed to derive the target OID; the reader hashes the same
    /// seed and recovers the same OID, so the body comes back without
    /// the caller ever materialising the target OID. This is the
    /// content-addressed contract the helper exists to provide.
    #[test]
    fn read_note_at_seed_round_trips_through_write_note_if_absent() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let _ = repo
            .write_note_if_absent(&nref, b"seed-A", b"body-A")
            .unwrap();
        let read_back = repo.read_note_at_seed(&nref, b"seed-A").unwrap();
        assert_eq!(read_back.as_deref(), Some(b"body-A".as_slice()));
    }

    /// When no note is attached under the seed, `read_note_at_seed`
    /// folds the absence into `Ok(None)` — same shape its underlying
    /// `read_note_if_present` exposes. The fresh-ref case (no ref
    /// at all) is one of the two absent branches `read_note_if_present`
    /// already pins; pinning it again at the seed-level helper guards
    /// against a future refactor that bypasses the absent-classifier.
    #[test]
    fn read_note_at_seed_returns_none_when_nothing_was_written() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let res = repo.read_note_at_seed(&nref, b"unwritten-seed").unwrap();
        assert!(res.is_none(), "expected None, got: {res:?}");
    }

    /// When a note is attached under a *different* seed, the asked-for
    /// seed still resolves to `None`. Exercises the "ref present, no
    /// note at this target" branch of the absent-classifier through
    /// the seed-level helper.
    #[test]
    fn read_note_at_seed_returns_none_when_other_seed_was_written() {
        let tmp = TempDir::new().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let _ = repo
            .write_note_if_absent(&nref, b"seed-A", b"body-A")
            .unwrap();
        let res = repo.read_note_at_seed(&nref, b"seed-B").unwrap();
        assert!(res.is_none(), "expected None for seed-B, got: {res:?}");
    }
}
