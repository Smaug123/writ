//! Filesystem helpers for the bare Git repository bailiff owns and
//! writ writes signed agent-run output into.
//!
//! Pre-v1 bailiff stores every artefact — plan submissions,
//! originating prompts, reviewer feedback, decisions, the signed
//! output envelopes writ produces — as Git blobs plus notes in a
//! single bare repo, host-side, separate from any workspace repo.
//! This module is the writ-side write surface for that repo: open or
//! create the bare repo, write a blob of arbitrary bytes, attach a
//! note to a target object under a caller-chosen notes ref. See
//! `docs/plans/2026-05-14-bailiff-split.md` for the wider context.
//!
//! **Bare only.** [`BailiffRepo::open`] validates that the directory
//! at `path` is a bare repo — `HEAD` exists and `core.bare = true` in
//! `<path>/config`. Refusing to open a non-bare path closes off the
//! "writ accidentally writes into a worktree" footgun: bailiff's repo
//! is host-side state, and a normal worktree (with files in
//! `<path>/...`) is a different kind of thing.
//!
//! **No force overwrites.** [`BailiffRepo::write_note`] uses `git
//! notes add` without `-f`, so attaching a second note to the same
//! target under the same ref is a typed error rather than a silent
//! replacement. Bailiff's lifecycle writes each artefact once;
//! double-writes are bugs to surface.
//!
//! **Subprocess hardening.** Every git invocation runs under the
//! same hardened environment `clean_git` uses for outgoing pushes:
//! `env_clear`, only the `CLEAN_GIT_CONFIG_*` / `HOME=/dev/null`
//! variables set, `cwd=/` so a stray config in the broker's working
//! directory cannot override anything. Identity (`GIT_AUTHOR_*` /
//! `GIT_COMMITTER_*`) is pinned to a synthetic `writ` user so
//! `git notes add` can create its notes-ref commit on hosts where
//! Git would otherwise refuse for lack of an auto-detected user.
//! Repo selection uses `--git-dir=<path>` rather than `-C <path>`:
//! that way even an existing `.git/` directory inside the bare
//! repo cannot redirect writes via Git's auto-discovery. Operations
//! on bailiff's repo are local, sub-second, and trusted, so we
//! don't replicate `clean_git`'s timeout + process-group SIGKILL
//! machinery — git exiting cleanly is the supervisor here, and any
//! hang would itself be a higher-priority bug than the things that
//! harness is built to contain.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::vm_git::{GitObjectId, GitObjectIdError};

use crate::core::NotesRef;

/// A handle to bailiff's bare Git repository on the local filesystem.
///
/// Construct via [`BailiffRepo::open`] (validates an existing bare
/// repo) or [`BailiffRepo::init_or_open`] (creates one on first run
/// then opens it). All handles to the same on-disk repo share the
/// same notes write lock — so concurrent `write_note` callers
/// serialize correctly even when they were opened independently
/// (not just cloned from one another).
#[derive(Clone, Debug)]
pub struct BailiffRepo {
    path: PathBuf,
    /// Absolute path of the `git` executable, resolved against the
    /// daemon's `PATH` at construction time. Stored here because
    /// every subprocess spawn `env_clear()`s the child environment
    /// (so it cannot rely on `PATH` itself), and because resolving
    /// against `PATH` after that point is too late: a Nix-style
    /// host without `/bin/git` would simply fail to spawn.
    git_program: PathBuf,
    /// Serialises `write_note` invocations against this repo.
    ///
    /// `git notes add` does not perform a compare-and-swap on the
    /// notes ref: it reads the current tip, builds a notes tree on
    /// top, then updates the ref. Two writers starting from the
    /// same tip would each build a tree containing only their own
    /// note, and the second ref update would silently overwrite
    /// the first — losing notes. An in-process mutex covers the
    /// existence check, `git notes add` invocation, and ref update
    /// as one critical section.
    ///
    /// The lock is shared across every `BailiffRepo` constructed
    /// for the same absolutised path (see `notes_lock_for`). A
    /// single per-handle mutex would only have serialised clones
    /// of one handle, leaving two callers who each `open`ed the
    /// same repo with independent locks — which is exactly the
    /// lost-update scenario the lock is supposed to prevent.
    ///
    /// Multi-process writers are not in scope: bailiff is a single
    /// daemon, and external git tooling touching the repo
    /// concurrently would be operator error.
    notes_write_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Process-wide registry mapping an absolutised repo path to the
/// notes write lock for that path. Stored as `Weak` so the entry
/// dies once the last `BailiffRepo` for that path drops, keeping
/// the table from accreting forever in tests or long-running
/// daemons that open many distinct repos.
static NOTES_WRITE_LOCKS: OnceLock<StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>> =
    OnceLock::new();

/// Look up (or create) the shared notes write lock for `path`. The
/// std `Mutex` around the registry is only held while we clone an
/// `Arc` or insert a new entry — no I/O happens under it — so it
/// never contends with the async `Mutex` that callers actually
/// take for their critical section.
fn notes_lock_for(path: &Path) -> Arc<tokio::sync::Mutex<()>> {
    let registry = NOTES_WRITE_LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = registry.lock().expect("notes-lock registry mutex poisoned");
    // Drop entries whose last handle is gone before searching, so
    // a stale `Weak` for `path` doesn't shadow a fresh insert.
    guard.retain(|_, weak| weak.strong_count() > 0);
    if let Some(weak) = guard.get(path)
        && let Some(strong) = weak.upgrade()
    {
        return strong;
    }
    let arc = Arc::new(tokio::sync::Mutex::new(()));
    guard.insert(path.to_path_buf(), Arc::downgrade(&arc));
    arc
}

impl BailiffRepo {
    /// The on-disk path of the bare repo.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the bare repository at `path`. Validates:
    /// - `path` exists and is a directory,
    /// - `<path>/HEAD` is a regular file (every git repo has one),
    /// - `<path>/config` exists and contains `bare = true`.
    ///
    /// The stored path is absolutized at construction. Every git
    /// invocation in this module runs with `cwd=/` (subprocess
    /// hardening), so a relative input would resolve differently on
    /// the host filesystem from the validation that happened in the
    /// daemon's working directory. Absolutizing once at the boundary
    /// keeps validation and operation pointing at the same bytes.
    ///
    /// Returns [`BailiffRepoError::NotABareRepo`] for any of the
    /// above failing — the operator's "I pointed writ at the wrong
    /// directory" path produces one typed error, not a grab-bag of
    /// I/O surprises.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, BailiffRepoError> {
        let path = absolutize(path.into())?;
        let git_program = resolve_git_program().await?;
        validate_bare_repo(&path).await?;
        let notes_write_lock = notes_lock_for(&path);
        Ok(Self {
            path,
            git_program,
            notes_write_lock,
        })
    }

    /// Open an existing bare repo at `path`, or create one there if
    /// the directory has no `HEAD` yet. Idempotent: the second call
    /// for the same path is a pure open. Equivalent to
    /// `git init --bare <path>` followed by [`open`](Self::open),
    /// with one safety twist: before creating a fresh repo, the
    /// target must be either non-existent or an empty directory.
    /// `git init --bare` will otherwise happily layer bare-repo
    /// files on top of a worktree (whose `HEAD` lives at
    /// `.git/HEAD`, so our top-level HEAD check sees nothing), and
    /// subsequent `git -C <path>` calls would then prefer the inner
    /// `.git/` directory git found — writes would silently leak into
    /// the workspace repo. Refusing to layer fixes that.
    pub async fn init_or_open(path: impl Into<PathBuf>) -> Result<Self, BailiffRepoError> {
        let path = absolutize(path.into())?;
        let git_program = resolve_git_program().await?;
        // `git init --bare` is itself idempotent — running it on an
        // existing bare repo is a no-op for the on-disk state — but
        // calling it unconditionally would also mean creating any
        // missing parent directories git would create on first run,
        // which we'd rather not do silently. So: only init if HEAD
        // is missing; then open the result either way, which is what
        // applies the bare-repo validation.
        let head_path = path.join("HEAD");
        if !head_path.exists() {
            if path.exists() {
                ensure_empty_directory(&path).await?;
            } else if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(BailiffRepoError::Io)?;
            }
            run_git_status(
                &git_program,
                &[OsStr::new("init"), OsStr::new("--bare"), path.as_os_str()],
                None,
            )
            .await?;
        }
        validate_bare_repo(&path).await?;
        let notes_write_lock = notes_lock_for(&path);
        Ok(Self {
            path,
            git_program,
            notes_write_lock,
        })
    }

    /// Write `bytes` as a loose Git blob into this repo and return
    /// the resulting object id. Wraps `git --git-dir=<path>
    /// hash-object -w --stdin`: identical bytes always produce the
    /// same OID (Git's content-addressing), so calling this twice
    /// for the same payload is harmless and returns the same value.
    ///
    /// `--git-dir` is preferred over `-C` so git operates on
    /// exactly the directory we hand it, even if that directory
    /// happens to contain a `.git/` subdirectory git would
    /// otherwise auto-discover.
    pub async fn write_blob(&self, bytes: &[u8]) -> Result<GitObjectId, BailiffRepoError> {
        let stdout = run_git_capture_stdout(
            &self.git_program,
            &[
                OsStr::new("--git-dir"),
                self.path.as_os_str(),
                OsStr::new("hash-object"),
                OsStr::new("-w"),
                OsStr::new("--stdin"),
            ],
            Some(bytes),
        )
        .await?;
        // `git hash-object` writes the 40-char OID followed by a
        // newline; trim then parse through our wire newtype rather
        // than trusting the stdout as-is.
        let raw = std::str::from_utf8(&stdout)
            .map_err(|_| BailiffRepoError::MalformedGitStdout {
                command: "hash-object",
            })?
            .trim();
        GitObjectId::new(raw).map_err(BailiffRepoError::GitObjectId)
    }

    /// Attach `body` as a git note under `notes_ref`, anchored at
    /// `target`. Refuses to overwrite an existing note at the same
    /// `(notes_ref, target)` pair — that surfaces as
    /// [`BailiffRepoError::NoteAlreadyExists`]. Bailiff writes each
    /// artefact once; a collision is a bug, not a routine condition.
    pub async fn write_note(
        &self,
        notes_ref: &NotesRef,
        target: &GitObjectId,
        body: &[u8],
    ) -> Result<(), BailiffRepoError> {
        // Hold the per-repo notes lock for the entire critical
        // section: the existence check + `git notes add`. Without
        // it, two concurrent writers starting from the same notes
        // tip would each build a tree containing only their own
        // note, and the second ref update would silently overwrite
        // the first.
        let _guard = self.notes_write_lock.lock().await;
        // Detect existing note up-front so we can return the typed
        // `NoteAlreadyExists` rather than the generic GitFailed that
        // `git notes add` (without `-f`) produces. The two-step shape
        // is also what lets us keep the write itself force-free.
        if note_exists(&self.git_program, &self.path, notes_ref, target).await? {
            return Err(BailiffRepoError::NoteAlreadyExists {
                notes_ref: notes_ref.as_str().to_string(),
                target: target.as_str().to_string(),
            });
        }
        let ref_arg = format!("--ref={}", notes_ref.as_str());
        // `--no-stripspace`: keep the exact stdin bytes. Default
        // `git notes add -F -` runs stripspace, which trims trailing
        // whitespace, collapses runs of blank lines, and adds a
        // single trailing newline. Bailiff stores signed payloads in
        // these notes; rewriting the bytes would corrupt any later
        // hash or signature check.
        //
        // `--allow-empty`: keep zero-byte bodies. Without it, an
        // empty stdin under `--no-stripspace` exits 0 but writes no
        // note. `write_note` claims a body was attached; honour that.
        run_git_status(
            &self.git_program,
            &[
                OsStr::new("--git-dir"),
                self.path.as_os_str(),
                OsStr::new("notes"),
                OsStr::new(&ref_arg),
                OsStr::new("add"),
                OsStr::new("--no-stripspace"),
                OsStr::new("--allow-empty"),
                OsStr::new("-F"),
                OsStr::new("-"),
                OsStr::new(target.as_str()),
            ],
            Some(body),
        )
        .await
    }
}

/// Resolve `path` lexically against the current working directory if
/// it is relative. No symlink resolution and no filesystem touch —
/// `std::path::absolute` does the minimum needed to make the result
/// independent of the subprocess `cwd` we later run git under.
fn absolutize(path: PathBuf) -> Result<PathBuf, BailiffRepoError> {
    std::path::absolute(&path).map_err(BailiffRepoError::Io)
}

/// Refuse to initialise a bare repo into a directory that already
/// contains anything. See [`BailiffRepo::init_or_open`] for the
/// rationale.
async fn ensure_empty_directory(path: &Path) -> Result<(), BailiffRepoError> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(BailiffRepoError::Io)?;
    if !meta.is_dir() {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: "path exists but is not a directory".to_string(),
        });
    }
    let mut entries = tokio::fs::read_dir(path)
        .await
        .map_err(BailiffRepoError::Io)?;
    if let Some(entry) = entries.next_entry().await.map_err(BailiffRepoError::Io)? {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: format!(
                "directory is non-empty (contains {:?}); refusing to layer a bare repo on top",
                entry.file_name()
            ),
        });
    }
    Ok(())
}

/// Check whether a note currently exists at `(notes_ref, target)`.
/// Implementation detail of `write_note` — `git notes list <target>`
/// exits 0 with the note OID on stdout when one exists, exits 1
/// when no note exists. Treat any other non-zero exit as a real
/// git failure rather than absence.
async fn note_exists(
    git_program: &Path,
    repo: &Path,
    notes_ref: &NotesRef,
    target: &GitObjectId,
) -> Result<bool, BailiffRepoError> {
    let ref_arg = format!("--ref={}", notes_ref.as_str());
    let outcome = run_git(
        git_program,
        &[
            OsStr::new("--git-dir"),
            repo.as_os_str(),
            OsStr::new("notes"),
            OsStr::new(&ref_arg),
            OsStr::new("list"),
            OsStr::new(target.as_str()),
        ],
        None,
        false,
    )
    .await?;
    match outcome.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(BailiffRepoError::GitFailed {
            command: "notes list",
            status: outcome.status,
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        }),
    }
}

async fn validate_bare_repo(path: &Path) -> Result<(), BailiffRepoError> {
    let dir_meta =
        tokio::fs::metadata(path)
            .await
            .map_err(|source| BailiffRepoError::NotABareRepo {
                path: path.display().to_string(),
                reason: format!("cannot stat: {source}"),
            })?;
    if !dir_meta.is_dir() {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: "not a directory".to_string(),
        });
    }
    let head = path.join("HEAD");
    if !head.is_file() {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: "missing HEAD".to_string(),
        });
    }
    let config = tokio::fs::read_to_string(path.join("config"))
        .await
        .map_err(|source| BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: format!("cannot read config: {source}"),
        })?;
    if !config_says_bare_true(&config) {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: "core.bare is not true".to_string(),
        });
    }
    // Reject non-SHA-1 object formats. `git init --bare
    // --object-format=sha256` produces a config with
    // `extensions.objectformat = sha256` and emits 64-char object
    // ids; our `GitObjectId` wire newtype only parses 40 hex chars,
    // so `write_blob` against a SHA-256 repo would fail on the
    // first call. Fail the validation instead, where the operator
    // sees one clear "not a bare repo we can use" error rather
    // than a downstream parse error on the first write.
    if let Some(format) = extensions_object_format(&config)
        && !format.eq_ignore_ascii_case("sha1")
    {
        return Err(BailiffRepoError::NotABareRepo {
            path: path.display().to_string(),
            reason: format!("extensions.objectformat = {format:?}; only sha1 is supported"),
        });
    }
    // Reject `commondir`: a gitdir containing this file delegates
    // its shared state (objects, refs, etc.) to the path named in
    // it. Subsequent `--git-dir <path>` writes would then land
    // outside the bare repo we validated. `git init --bare` does
    // not produce this file; its presence means the directory is
    // a linked-worktree gitdir or was hand-crafted to redirect
    // writes — neither of which we accept.
    match tokio::fs::metadata(path.join("commondir")).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(BailiffRepoError::Io(source)),
        Ok(_) => {
            return Err(BailiffRepoError::NotABareRepo {
                path: path.display().to_string(),
                reason:
                    "gitdir contains `commondir`; bare repos must not redirect their common dir"
                        .to_string(),
            });
        }
    }
    Ok(())
}

/// Read `extensions.objectformat` from a Git config, if present.
/// SHA-1 repos omit this key entirely (the default), so a `None`
/// here means SHA-1, not "unparseable config". Anything else
/// (notably `sha256`) is what we reject upstream.
fn extensions_object_format(text: &str) -> Option<String> {
    let mut in_extensions = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_extensions = section.eq_ignore_ascii_case("extensions");
            continue;
        }
        if !in_extensions {
            continue;
        }
        if let Some((key, val)) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
            && key.eq_ignore_ascii_case("objectformat")
        {
            return Some(val.to_string());
        }
    }
    None
}

/// Minimal INI-style scan for `bare = true` under `[core]`. Git's
/// own config grammar is richer (subsection syntax, includes,
/// quoting), but the `git init --bare` output is the well-known
/// form, and that's the one we need to accept here. A non-trivially-
/// edited config that nonetheless represents `core.bare = true` will
/// fail this check — at which point the operator's recourse is "use
/// the standard layout `git init --bare` writes." That's a fair
/// constraint for v1 since writ is the only writer here.
fn config_says_bare_true(text: &str) -> bool {
    let mut in_core = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_core = section.eq_ignore_ascii_case("core");
            continue;
        }
        if !in_core {
            continue;
        }
        if let Some(value) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
            let (key, val) = value;
            if key.eq_ignore_ascii_case("bare") && val.eq_ignore_ascii_case("true") {
                return true;
            }
        }
    }
    false
}

/// Outcome of one local `git` invocation: exit status plus any
/// captured stdout / stderr. Internal to this module.
struct GitOutcome {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run `git` once with the hardened environment and return the full
/// outcome (status + stdout + stderr) without classifying it as
/// success or failure. Callers decide what's success — `git notes
/// list` legitimately exits 1 for "no note here", whereas `git
/// init` returning non-zero is always an error.
async fn run_git(
    git_program: &Path,
    args: &[&OsStr],
    stdin_via: Option<&[u8]>,
    capture_stdout: bool,
) -> Result<GitOutcome, BailiffRepoError> {
    let mut command = Command::new(git_program);
    command.env_clear();
    for (name, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(name, value);
    }
    command.current_dir(CLEAN_GIT_CURRENT_DIR);
    command.args(args);
    command.stdin(if stdin_via.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(if capture_stdout {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stderr(Stdio::piped());
    // If the caller's future is dropped between spawn and reap
    // (request cancellation, daemon shutdown), tokio would by
    // default leak the child process. That would release
    // `notes_write_lock` while a `git notes add` is still updating
    // the ref, so a subsequent writer could race with it and lose
    // notes despite the mutex. `kill_on_drop` ties the child's
    // lifetime to the future's.
    command.kill_on_drop(true);

    let mut child = command.spawn().map_err(BailiffRepoError::Spawn)?;
    if let Some(bytes) = stdin_via {
        let mut stdin = child
            .stdin
            .take()
            .expect("stdin was configured as Stdio::piped()");
        stdin.write_all(bytes).await.map_err(BailiffRepoError::Io)?;
        // Drop closes the pipe so `hash-object --stdin` sees EOF.
        drop(stdin);
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(BailiffRepoError::Io)?;
    Ok(GitOutcome {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// Run `git` once and require a successful (status-zero) exit.
/// Used for commands that have no "expected non-zero" branch
/// (`init`, `notes add`).
async fn run_git_status(
    git_program: &Path,
    args: &[&OsStr],
    stdin_via: Option<&[u8]>,
) -> Result<(), BailiffRepoError> {
    let label = describe_args(args);
    let outcome = run_git(git_program, args, stdin_via, false).await?;
    if outcome.status.success() {
        Ok(())
    } else {
        Err(BailiffRepoError::GitFailed {
            command: label,
            status: outcome.status,
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        })
    }
}

/// Run `git` once, require success, and return captured stdout.
async fn run_git_capture_stdout(
    git_program: &Path,
    args: &[&OsStr],
    stdin_via: Option<&[u8]>,
) -> Result<Vec<u8>, BailiffRepoError> {
    let label = describe_args(args);
    let outcome = run_git(git_program, args, stdin_via, true).await?;
    if outcome.status.success() {
        Ok(outcome.stdout)
    } else {
        Err(BailiffRepoError::GitFailed {
            command: label,
            status: outcome.status,
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        })
    }
}

/// Resolve `git` against the daemon's `PATH` once, before any
/// subprocess clears its environment. Without this, a host where
/// `git` is supplied solely via `PATH` (Nix, custom CI toolchains)
/// would fail at spawn time: `Command::new("git")` performs the
/// lookup at spawn, after `env_clear()` has already wiped `PATH`.
async fn resolve_git_program() -> Result<PathBuf, BailiffRepoError> {
    crate::clean_git::resolve_program_for_clean_env(Path::new("git"))
        .await
        .map_err(|source| BailiffRepoError::ResolveGit(source.to_string()))
}

/// Pick a human-readable label for the failing command — the first
/// non-flag argv slot, which is the git subcommand for our
/// invocations (`init`, `hash-object`, `notes`). Falls back to
/// `"git"` so the error message is never empty.
fn describe_args(args: &[&OsStr]) -> &'static str {
    for arg in args {
        let s = arg.to_string_lossy();
        if s.starts_with('-') {
            continue;
        }
        return match s.as_ref() {
            "init" => "init",
            "hash-object" => "hash-object",
            "notes" => "notes",
            "cat-file" => "cat-file",
            _ => "git",
        };
    }
    "git"
}

/// Mirrors `clean_git`'s outgoing-push hardening: clear inherited
/// `GIT_CONFIG_*`, point HOME at `/dev/null` so per-user config
/// cannot influence the child. Kept as a private duplicate rather
/// than imported because the public surface in `clean_git` is
/// `pub(crate)` and tied to a different timeout/process-group
/// regime that this module's short-lived local invocations don't
/// need.
///
/// The `GIT_AUTHOR_*` / `GIT_COMMITTER_*` slots are pinned to a
/// fixed `writ` identity because `git notes add` creates a commit
/// on the notes ref, and a commit needs an author/committer. With
/// system and global config disabled, hosts that can't auto-detect
/// a user identity (containers, CI machines) would otherwise see
/// every `write_note` fail. Bailiff's notes commits are internal
/// machinery, never published as user-attributed history, so a
/// stable synthetic identity is what we want.
const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 8] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("HOME", "/dev/null"),
    ("GIT_AUTHOR_NAME", "writ"),
    ("GIT_AUTHOR_EMAIL", "writ@invalid"),
    ("GIT_COMMITTER_NAME", "writ"),
    ("GIT_COMMITTER_EMAIL", "writ@invalid"),
];

/// Run git from `/` so a stray `.git/config` in whatever directory
/// writ happens to be launched from cannot rewrite anything.
const CLEAN_GIT_CURRENT_DIR: &str = "/";

#[derive(Debug, thiserror::Error)]
pub enum BailiffRepoError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("could not resolve `git` on PATH: {0}")]
    ResolveGit(String),
    #[error("could not spawn git: {0}")]
    Spawn(std::io::Error),
    #[error("{path:?} is not a bare git repository: {reason}")]
    NotABareRepo { path: String, reason: String },
    #[error("`git {command}` exited with {status}: {stderr}")]
    GitFailed {
        command: &'static str,
        status: ExitStatus,
        stderr: String,
    },
    #[error("`git {command}` produced non-UTF-8 stdout where an object id was expected")]
    MalformedGitStdout { command: &'static str },
    #[error("`git hash-object` returned an unparseable object id: {0}")]
    GitObjectId(GitObjectIdError),
    #[error("note already exists under {notes_ref:?} at {target:?}")]
    NoteAlreadyExists { notes_ref: String, target: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap()
    }

    /// Tests run git through the same wrapper helpers as production
    /// code, which now require a resolved `git` path. Resolve once
    /// per call rather than caching, because each test runs in its
    /// own tokio runtime and `tokio::sync::OnceCell` would tie a
    /// cached value to the first runtime that touched it.
    async fn git_program() -> PathBuf {
        resolve_git_program().await.unwrap()
    }

    /// `init_or_open` on a fresh empty directory must produce a
    /// bare repo: HEAD + `core.bare = true`. The stored path must
    /// also come back absolute, since downstream git invocations
    /// run with `cwd=/`.
    #[tokio::test]
    async fn init_or_open_creates_a_bare_repo() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("bailiff-repo");
        let repo = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        assert!(
            repo.path().is_absolute(),
            "stored path should be absolute, got {:?}",
            repo.path()
        );
        assert!(repo_path.join("HEAD").is_file());
        let config = std::fs::read_to_string(repo_path.join("config")).unwrap();
        assert!(
            config_says_bare_true(&config),
            "expected core.bare = true, got config:\n{config}"
        );
    }

    /// `init_or_open` on a path that already holds a bare repo must
    /// open it as-is (idempotent boot path).
    #[tokio::test]
    async fn init_or_open_is_idempotent_on_existing_bare_repo() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("bailiff-repo");
        let _ = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        // Capture HEAD's mtime so we can prove the second call did
        // not re-initialise.
        let head_meta_before = std::fs::metadata(repo_path.join("HEAD")).unwrap();
        let modified_before = head_meta_before.modified().unwrap();
        let _ = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        let modified_after = std::fs::metadata(repo_path.join("HEAD"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            modified_before, modified_after,
            "HEAD was rewritten on the idempotent path"
        );
    }

    /// `open` against a directory that is not a bare git repo must
    /// surface the typed `NotABareRepo` rather than any I/O-shaped
    /// error.
    #[tokio::test]
    async fn open_rejects_a_plain_directory() {
        let dir = TempDir::new().unwrap();
        let err = BailiffRepo::open(dir.path()).await.unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NotABareRepo { .. }),
            "got: {err:?}"
        );
    }

    /// `open` must reject a plain (non-bare) git repo: bailiff's repo
    /// is host-side state, and a worktree at that path means the
    /// operator pointed writ at the wrong directory. Pointing at a
    /// `git init`-produced worktree fails the very first invariant
    /// (no `HEAD` at the top level — it lives in `.git/HEAD`), which
    /// is enough for the rejection. The `core.bare = false` arm is
    /// covered separately by `open_rejects_a_directory_with_bare_false`.
    #[tokio::test]
    async fn open_rejects_a_non_bare_worktree() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("worktree");
        let git = git_program().await;
        run_git_status(
            &git,
            &[
                OsStr::new("init"),
                OsStr::new("--initial-branch=main"),
                repo_path.as_os_str(),
            ],
            None,
        )
        .await
        .unwrap();
        let err = BailiffRepo::open(&repo_path).await.unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NotABareRepo { .. }),
            "got: {err:?}"
        );
    }

    /// A directory that has a `HEAD` and a `config` but where
    /// `core.bare = false` must reject with a reason that mentions
    /// the bare check, since this is the arm of `validate_bare_repo`
    /// that the worktree test cannot reach.
    #[tokio::test]
    async fn open_rejects_a_directory_with_bare_false() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("not-bare");
        std::fs::create_dir(&repo_path).unwrap();
        std::fs::write(repo_path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            repo_path.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        )
        .unwrap();
        let err = BailiffRepo::open(&repo_path).await.unwrap_err();
        match err {
            BailiffRepoError::NotABareRepo { reason, .. } => {
                assert!(
                    reason.contains("bare"),
                    "reason should mention bare-ness, got: {reason}"
                );
            }
            other => panic!("expected NotABareRepo, got {other:?}"),
        }
    }

    /// `write_blob` round-trips through `git cat-file -p`: bytes
    /// in, bytes out, OID matches the wire newtype.
    #[tokio::test]
    async fn write_blob_round_trips_through_cat_file() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();

        let payload = b"hello-bailiff";
        let oid = repo.write_blob(payload).await.unwrap();
        assert_eq!(oid.as_str().len(), 40);

        let git = git_program().await;
        let stdout = run_git_capture_stdout(
            &git,
            &[
                OsStr::new("-C"),
                repo.path().as_os_str(),
                OsStr::new("cat-file"),
                OsStr::new("-p"),
                OsStr::new(oid.as_str()),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(stdout, payload);
    }

    /// Git content-addresses blobs by SHA-1 of the framed payload,
    /// so writing identical bytes twice must return the same OID
    /// (idempotent retry is safe).
    #[tokio::test]
    async fn write_blob_is_content_addressed() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let a = repo.write_blob(b"same bytes").await.unwrap();
        let b = repo.write_blob(b"same bytes").await.unwrap();
        assert_eq!(a, b);
        let c = repo.write_blob(b"different bytes").await.unwrap();
        assert_ne!(a, c);
    }

    /// `write_note` attaches `body` so `git notes show` retrieves
    /// the same bytes. Demonstrates that the (ref, target) shape
    /// the wire protocol envisions is what the helper actually
    /// writes.
    #[tokio::test]
    async fn write_note_attaches_retrievable_body() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let target = repo.write_blob(b"payload").await.unwrap();
        let r = notes_ref();
        repo.write_note(&r, &target, b"note body for that payload")
            .await
            .unwrap();

        let git = git_program().await;
        let ref_arg = format!("--ref={}", r.as_str());
        let stdout = run_git_capture_stdout(
            &git,
            &[
                OsStr::new("-C"),
                repo.path().as_os_str(),
                OsStr::new("notes"),
                OsStr::new(&ref_arg),
                OsStr::new("show"),
                OsStr::new(target.as_str()),
            ],
            None,
        )
        .await
        .unwrap();
        // With `--no-stripspace` the stored bytes equal the input
        // bytes; `git notes show` writes them verbatim.
        assert_eq!(stdout.as_slice(), b"note body for that payload");
    }

    /// A second `write_note` to the same (ref, target) must surface
    /// `NoteAlreadyExists` rather than silently overwrite. Bailiff
    /// writes each artefact once; a collision is a bug to surface.
    #[tokio::test]
    async fn write_note_refuses_to_overwrite_existing_note() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let target = repo.write_blob(b"payload").await.unwrap();
        let r = notes_ref();
        repo.write_note(&r, &target, b"first").await.unwrap();
        let err = repo.write_note(&r, &target, b"second").await.unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NoteAlreadyExists { .. }),
            "got: {err:?}"
        );

        // Sanity: the original note is still there, unmodified.
        let git = git_program().await;
        let ref_arg = format!("--ref={}", r.as_str());
        let stdout = run_git_capture_stdout(
            &git,
            &[
                OsStr::new("-C"),
                repo.path().as_os_str(),
                OsStr::new("notes"),
                OsStr::new(&ref_arg),
                OsStr::new("show"),
                OsStr::new(target.as_str()),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(stdout.as_slice(), b"first");
    }

    /// Distinct notes refs are independent: writing a note to one
    /// ref must not collide with the same target on another ref.
    #[tokio::test]
    async fn write_note_isolates_by_notes_ref() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let target = repo.write_blob(b"payload").await.unwrap();
        let r1 = NotesRef::try_new("refs/notes/writ/a").unwrap();
        let r2 = NotesRef::try_new("refs/notes/writ/b").unwrap();
        repo.write_note(&r1, &target, b"under a").await.unwrap();
        repo.write_note(&r2, &target, b"under b").await.unwrap();
        let git = git_program().await;
        // Both notes are independently retrievable.
        for (r, body) in [(&r1, b"under a".as_slice()), (&r2, b"under b".as_slice())] {
            let ref_arg = format!("--ref={}", r.as_str());
            let stdout = run_git_capture_stdout(
                &git,
                &[
                    OsStr::new("-C"),
                    repo.path().as_os_str(),
                    OsStr::new("notes"),
                    OsStr::new(&ref_arg),
                    OsStr::new("show"),
                    OsStr::new(target.as_str()),
                ],
                None,
            )
            .await
            .unwrap();
            assert_eq!(stdout.as_slice(), body);
        }
    }

    /// `init_or_open` must refuse to layer a bare repo onto an
    /// existing worktree. The worktree carries its `HEAD` under
    /// `.git/HEAD`, so the top-level HEAD check would otherwise
    /// see nothing and proceed with `git init --bare`, after which
    /// `git -C <path>` would prefer the inner `.git/` and writes
    /// would leak into the workspace repo.
    #[tokio::test]
    async fn init_or_open_refuses_to_init_into_existing_worktree() {
        let dir = TempDir::new().unwrap();
        let worktree = dir.path().join("worktree");
        let git = git_program().await;
        // Plain (non-bare) init plants a `.git/` directory under
        // `worktree/`, marking it as a worktree.
        run_git_status(
            &git,
            &[
                OsStr::new("init"),
                OsStr::new("--initial-branch=main"),
                worktree.as_os_str(),
            ],
            None,
        )
        .await
        .unwrap();
        let err = BailiffRepo::init_or_open(&worktree).await.unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NotABareRepo { .. }),
            "got: {err:?}"
        );
        // The worktree's `.git/` must still be intact: we refused
        // to touch it.
        assert!(
            worktree.join(".git").is_dir(),
            "worktree .git was disturbed"
        );
    }

    /// `init_or_open` must refuse to layer a bare repo onto a
    /// directory that already contains unrelated files — same
    /// rationale as the worktree case, but for the more general
    /// "operator pointed writ at a directory with stuff in it" path.
    #[tokio::test]
    async fn init_or_open_refuses_to_init_into_non_empty_directory() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("not-empty");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("README"), b"not for bailiff").unwrap();
        let err = BailiffRepo::init_or_open(&target).await.unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NotABareRepo { .. }),
            "got: {err:?}"
        );
        // The stray file is untouched.
        assert_eq!(
            std::fs::read(target.join("README")).unwrap(),
            b"not for bailiff"
        );
    }

    /// `write_note` must round-trip exact bytes, including bodies
    /// that would be mangled by Git's default `stripspace` (trailing
    /// whitespace trimmed, runs of blank lines collapsed, etc.). The
    /// notes carry signed payloads downstream, so byte-for-byte
    /// preservation is load-bearing.
    #[tokio::test]
    async fn write_note_preserves_exact_bytes_including_whitespace() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let git = git_program().await;
        let cases: &[&[u8]] = &[
            b"no trailing newline",
            b"with trailing newline\n",
            b"multiple trailing newlines\n\n\n",
            b"   leading whitespace",
            b"trailing whitespace   ",
            b"interior\n\n\n blank lines",
        ];
        for (i, body) in cases.iter().enumerate() {
            let target = repo
                .write_blob(format!("payload-{i}").as_bytes())
                .await
                .unwrap();
            let r = NotesRef::try_new(format!("refs/notes/writ/case-{i}")).unwrap();
            repo.write_note(&r, &target, body).await.unwrap();
            let ref_arg = format!("--ref={}", r.as_str());
            let stdout = run_git_capture_stdout(
                &git,
                &[
                    OsStr::new("-C"),
                    repo.path().as_os_str(),
                    OsStr::new("notes"),
                    OsStr::new(&ref_arg),
                    OsStr::new("show"),
                    OsStr::new(target.as_str()),
                ],
                None,
            )
            .await
            .unwrap();
            assert_eq!(
                stdout.as_slice(),
                *body,
                "body {i} round-trip changed bytes"
            );
        }
    }

    /// An empty note body is legitimate: `write_note` should attach
    /// a zero-byte note, and `git notes list` should report it.
    #[tokio::test]
    async fn write_note_accepts_empty_body() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let target = repo.write_blob(b"anchor").await.unwrap();
        let r = notes_ref();
        repo.write_note(&r, &target, b"").await.unwrap();
        let git = git_program().await;
        let ref_arg = format!("--ref={}", r.as_str());
        let stdout = run_git_capture_stdout(
            &git,
            &[
                OsStr::new("-C"),
                repo.path().as_os_str(),
                OsStr::new("notes"),
                OsStr::new(&ref_arg),
                OsStr::new("show"),
                OsStr::new(target.as_str()),
            ],
            None,
        )
        .await
        .unwrap();
        assert!(
            stdout.is_empty(),
            "expected empty note body, got {stdout:?}"
        );
    }

    /// Even if a `.git/` directory sneaks into the bare repo
    /// somehow, `write_blob` and `write_note` must still write to
    /// the bare repo (objects under `<path>/objects/...`), not to
    /// the inner repo Git would auto-discover. This is why the
    /// production helpers use `--git-dir=<path>` rather than
    /// `-C <path>`: the latter would let Git's repo discovery
    /// pick the inner `.git/` instead of the directory we handed
    /// it.
    #[tokio::test]
    async fn write_uses_explicit_git_dir_even_when_dot_git_exists() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("bare");
        let repo = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        // Plant a real working repo inside the bare repo. Without
        // `--git-dir`, `git -C <repo_path>` would pick this up.
        let decoy = repo_path.join(".git");
        let git = git_program().await;
        run_git_status(
            &git,
            &[
                OsStr::new("init"),
                OsStr::new("--initial-branch=main"),
                decoy.as_os_str(),
            ],
            None,
        )
        .await
        .unwrap();
        // After this, `repo_path/.git/` is a worktree-style repo.

        let oid = repo.write_blob(b"bailiff-only").await.unwrap();

        // The object must land under the bare repo's objects/ tree.
        let prefix = &oid.as_str()[..2];
        let rest = &oid.as_str()[2..];
        let bare_object = repo_path.join("objects").join(prefix).join(rest);
        assert!(
            bare_object.exists(),
            "blob should live in the bare repo, expected at {bare_object:?}"
        );
        // And not in the decoy worktree's objects.
        let decoy_object = decoy.join("objects").join(prefix).join(rest);
        assert!(
            !decoy_object.exists(),
            "blob leaked into the inner .git: {decoy_object:?}"
        );
    }

    /// Concurrent `write_note` calls to the same notes ref must
    /// both end up retrievable. Without the per-repo lock, each
    /// `git notes add` would start from the empty ref tip and the
    /// second ref update would overwrite the first, silently
    /// losing one of the two notes.
    #[tokio::test]
    async fn write_note_serializes_concurrent_writes_to_same_ref() {
        let dir = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(dir.path().join("repo"))
            .await
            .unwrap();
        let r = notes_ref();
        let target_a = repo.write_blob(b"payload-a").await.unwrap();
        let target_b = repo.write_blob(b"payload-b").await.unwrap();

        // Two concurrent write_note futures, same ref, distinct
        // targets. Both must succeed; both notes must be present
        // afterwards.
        let repo_a = repo.clone();
        let repo_b = repo.clone();
        let r_a = r.clone();
        let r_b = r.clone();
        let ta = target_a.clone();
        let tb = target_b.clone();
        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { repo_a.write_note(&r_a, &ta, b"note-a").await }),
            tokio::spawn(async move { repo_b.write_note(&r_b, &tb, b"note-b").await }),
        );
        res_a.unwrap().unwrap();
        res_b.unwrap().unwrap();

        // Both notes must be retrievable through the bare repo's
        // notes ref — proving the second writer rebased onto the
        // first instead of clobbering it.
        let git = git_program().await;
        for (target, expected) in [(&target_a, b"note-a"), (&target_b, b"note-b")] {
            let ref_arg = format!("--ref={}", r.as_str());
            let stdout = run_git_capture_stdout(
                &git,
                &[
                    OsStr::new("--git-dir"),
                    repo.path().as_os_str(),
                    OsStr::new("notes"),
                    OsStr::new(&ref_arg),
                    OsStr::new("show"),
                    OsStr::new(target.as_str()),
                ],
                None,
            )
            .await
            .unwrap();
            assert_eq!(stdout.as_slice(), expected.as_slice());
        }
    }

    /// A gitdir with a `commondir` file points objects and refs
    /// elsewhere. If validation accepts such a directory, writes
    /// would land outside the bailiff repo. Refuse it.
    #[tokio::test]
    async fn open_rejects_a_gitdir_with_commondir() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("redirected");
        // First seed a real bare repo so HEAD and config(bare=true)
        // pass, then plant a `commondir` file alongside them.
        let _ = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        std::fs::write(repo_path.join("commondir"), "/some/other/path\n").unwrap();
        let err = BailiffRepo::open(&repo_path).await.unwrap_err();
        match err {
            BailiffRepoError::NotABareRepo { reason, .. } => {
                assert!(
                    reason.contains("commondir"),
                    "reason should mention commondir, got: {reason}"
                );
            }
            other => panic!("expected NotABareRepo, got {other:?}"),
        }
    }

    /// `absolutize` must turn a relative path into an absolute one
    /// without touching the filesystem. The downstream guarantee —
    /// that the path stored in `BailiffRepo` is independent of the
    /// subprocess `cwd=/` we later run git under — rides on this.
    #[test]
    fn absolutize_makes_relative_paths_absolute() {
        let out = absolutize(PathBuf::from("some/relative/thing")).unwrap();
        assert!(out.is_absolute(), "expected absolute, got {out:?}");
    }

    /// And an already-absolute path must come back absolute too
    /// (i.e. `absolutize` doesn't accidentally re-relativise).
    #[test]
    fn absolutize_preserves_already_absolute_paths() {
        let input = PathBuf::from("/tmp/some-bare-repo");
        let out = absolutize(input.clone()).unwrap();
        assert!(out.is_absolute(), "expected absolute, got {out:?}");
    }

    #[test]
    fn config_parser_accepts_canonical_bare_repo_config() {
        let canonical = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n";
        assert!(config_says_bare_true(canonical));
    }

    #[test]
    fn config_parser_accepts_non_canonical_whitespace_and_case() {
        let weird = "[CORE]\nbare=True\n";
        assert!(config_says_bare_true(weird));
    }

    #[test]
    fn config_parser_rejects_bare_false() {
        let plain = "[core]\nbare = false\n";
        assert!(!config_says_bare_true(plain));
    }

    /// `bare = true` outside `[core]` must not satisfy the check —
    /// the field is scoped to that section.
    #[test]
    fn config_parser_rejects_bare_true_outside_core_section() {
        let misplaced = "[remote \"foo\"]\nbare = true\n";
        assert!(!config_says_bare_true(misplaced));
    }

    /// A commented-out `bare = true` must not pass — git would
    /// ignore it, so we do too.
    #[test]
    fn config_parser_ignores_commented_lines() {
        let commented = "[core]\n# bare = true\n";
        assert!(!config_says_bare_true(commented));
    }

    /// SHA-1 (default) repos have no `extensions.objectformat`
    /// entry. Treat absence as SHA-1, not as "could not parse".
    #[test]
    fn extensions_parser_returns_none_when_objectformat_is_unset() {
        let sha1_repo = "[core]\n\trepositoryformatversion = 0\n\tbare = true\n";
        assert_eq!(extensions_object_format(sha1_repo), None);
    }

    /// `git init --bare --object-format=sha256` writes a config
    /// shaped like this — the parser must read it back as
    /// `Some("sha256")` so validation can reject the repo.
    #[test]
    fn extensions_parser_finds_sha256_object_format() {
        let sha256_repo = "[extensions]\n\tobjectformat = sha256\n[core]\n\trepositoryformatversion = 1\n\tbare = true\n";
        assert_eq!(
            extensions_object_format(sha256_repo)
                .as_deref()
                .map(str::to_ascii_lowercase),
            Some("sha256".to_string())
        );
    }

    /// `objectformat` in the wrong section must not satisfy the
    /// check — the field is scoped to `[extensions]`.
    #[test]
    fn extensions_parser_ignores_objectformat_outside_extensions() {
        let misplaced = "[core]\n\tobjectformat = sha256\n\tbare = true\n";
        assert_eq!(extensions_object_format(misplaced), None);
    }

    /// `open` against a SHA-256 bare repo must reject up front:
    /// the rest of the module assumes 40-char SHA-1 object ids,
    /// and `GitObjectId::new` would refuse the 64-char IDs git
    /// hands back from a SHA-256 repo on the first `write_blob`.
    /// Fail at validation time so the operator sees one clear
    /// "not a bare repo we can use" error rather than a downstream
    /// parse error.
    #[tokio::test]
    async fn open_rejects_a_sha256_repo() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("sha256-repo");
        let git = git_program().await;
        // `git init --bare --object-format=sha256` does the
        // honest thing for us: it writes the exact config layout
        // we want to reject in validation.
        let init = run_git_status(
            &git,
            &[
                OsStr::new("init"),
                OsStr::new("--bare"),
                OsStr::new("--object-format=sha256"),
                repo_path.as_os_str(),
            ],
            None,
        )
        .await;
        // Some git builds disable SHA-256 support. Skip the test
        // (cleanly) rather than fail it on those hosts — the
        // validation logic is also exercised by the parser unit
        // tests above and `validate_bare_repo` directly below.
        if init.is_err() {
            return;
        }
        let err = BailiffRepo::open(&repo_path).await.unwrap_err();
        match err {
            BailiffRepoError::NotABareRepo { reason, .. } => {
                assert!(
                    reason.to_ascii_lowercase().contains("sha"),
                    "reason should mention the object format, got: {reason}"
                );
            }
            other => panic!("expected NotABareRepo, got {other:?}"),
        }
    }

    /// Hand-craft a config that satisfies every other check (bare
    /// = true, HEAD present, no commondir) but declares
    /// `extensions.objectformat = sha256`. This exercises the
    /// SHA-256 rejection branch even on hosts whose `git` was
    /// built without SHA-256 support.
    #[tokio::test]
    async fn open_rejects_a_directory_with_sha256_in_config() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("sha256-by-hand");
        std::fs::create_dir(&repo_path).unwrap();
        std::fs::write(repo_path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            repo_path.join("config"),
            "[extensions]\n\tobjectformat = sha256\n[core]\n\trepositoryformatversion = 1\n\tbare = true\n",
        )
        .unwrap();
        let err = BailiffRepo::open(&repo_path).await.unwrap_err();
        match err {
            BailiffRepoError::NotABareRepo { reason, .. } => {
                assert!(
                    reason.to_ascii_lowercase().contains("sha"),
                    "reason should mention the object format, got: {reason}"
                );
            }
            other => panic!("expected NotABareRepo, got {other:?}"),
        }
    }

    /// Two `BailiffRepo` handles independently `open`ed against
    /// the same path must share their `write_note` mutex — without
    /// that, concurrent writers through different handles bypass
    /// the lock entirely and the second `git notes add` overwrites
    /// the first, silently losing a note.
    #[tokio::test]
    async fn write_note_serializes_across_distinct_handles_to_same_path() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("repo");
        let first = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        let second = BailiffRepo::open(&repo_path).await.unwrap();
        let target_a = first.write_blob(b"payload-a").await.unwrap();
        let target_b = first.write_blob(b"payload-b").await.unwrap();
        let r = notes_ref();

        let r_a = r.clone();
        let r_b = r.clone();
        let ta = target_a.clone();
        let tb = target_b.clone();
        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { first.write_note(&r_a, &ta, b"note-a").await }),
            tokio::spawn(async move { second.write_note(&r_b, &tb, b"note-b").await }),
        );
        res_a.unwrap().unwrap();
        res_b.unwrap().unwrap();

        let git = git_program().await;
        for (target, expected) in [(&target_a, b"note-a"), (&target_b, b"note-b")] {
            let ref_arg = format!("--ref={}", r.as_str());
            let stdout = run_git_capture_stdout(
                &git,
                &[
                    OsStr::new("--git-dir"),
                    repo_path.as_os_str(),
                    OsStr::new("notes"),
                    OsStr::new(&ref_arg),
                    OsStr::new("show"),
                    OsStr::new(target.as_str()),
                ],
                None,
            )
            .await
            .unwrap();
            assert_eq!(
                stdout.as_slice(),
                expected.as_slice(),
                "note for {target:?} did not survive concurrent writes through distinct handles"
            );
        }
    }

    /// Two `BailiffRepo` handles against the *same* path must point
    /// at the same `tokio::sync::Mutex` instance — i.e. the lookup
    /// returns one underlying `Arc` for both, not two equally-shaped
    /// but distinct ones. This is the structural invariant behind
    /// `write_note_serializes_across_distinct_handles_to_same_path`.
    #[tokio::test]
    async fn notes_lock_for_returns_same_arc_per_path() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("repo");
        let first = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        let second = BailiffRepo::open(&repo_path).await.unwrap();
        assert!(
            Arc::ptr_eq(&first.notes_write_lock, &second.notes_write_lock),
            "handles to the same path must share one notes-write lock"
        );

        // Distinct path → distinct lock. Otherwise we'd serialise
        // writes across unrelated repos, which would be a
        // correctness bug in the other direction (deadlocks across
        // independent operations).
        let other_path = dir.path().join("repo-2");
        let other = BailiffRepo::init_or_open(&other_path).await.unwrap();
        assert!(
            !Arc::ptr_eq(&first.notes_write_lock, &other.notes_write_lock),
            "handles to distinct paths must NOT share a lock"
        );
    }
}
