//! Bare-repo helpers for bailiff's note-storage backend.
//!
//! Bailiff persists every writ-signed run as a Git note in a host-side
//! bare repo it owns. This module is the thin wrapper that opens the
//! repo, validates it matches the shape bailiff expects, and attaches
//! note bodies to per-run seed OIDs under caller-supplied notes refs.
//! See `docs/plans/2026-05-14-bailiff-split.md` slice B for the wider
//! context.
//!
//! ## Threat model
//!
//! Bailiff *owns* its bare repo and is the sole writer (via writ,
//! through this module). The validation below defends against operator
//! error and on-disk corruption, not against an attacker who can write
//! to bailiff's filesystem: a host that can mutate the repo can also
//! forge the signing key, so adversarial-config rejections buy nothing
//! on top. The minimum check surface — pinned at the top of the slice
//! before any code was written — is:
//!
//! * `HEAD` present (a directory with no HEAD is not a Git repo).
//! * `core.bare = true` via `git config --bool --get`, which uses
//!   Git's own parser and gives us last-wins handling for free.
//! * `objects/` and `refs/` exist as directories (so the bare layout
//!   is at least plausibly intact).
//! * `commondir` is absent at the top level (a worktree of a different
//!   repo would have this file and is not what bailiff wants to write
//!   notes into).
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
//! `init.defaultObjectFormat` setting can subvert bailiff's repo.
//! We then point git at the repo via `--git-dir=<canonical_path>`
//! instead of bare-repo discovery, which a hardened host can
//! disable. See the `prepare_git_command` helper.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::clean_git::CLEAN_GIT_CONFIG_ENV;
use crate::core::NotesRef;
use crate::vm_git::{GitObjectId, GitObjectIdError};

/// A validated handle on bailiff's bare notes repo.
///
/// Construct via [`BailiffRepo::open`] (validation only) or
/// [`BailiffRepo::init_or_open`] (initialise an empty bare repo on
/// first run, then validate). The wrapped path is the canonicalised
/// filesystem location; the canonical form is what the per-repo
/// notes-write mutex is keyed on, so two `BailiffRepo` handles for
/// the same on-disk repo share the same lock.
#[derive(Debug)]
pub struct BailiffRepo {
    canonical_path: PathBuf,
}

impl BailiffRepo {
    /// Open an existing bare repo at `path` after running the pinned
    /// minimal validation. The path is canonicalised so multiple
    /// handles for the same repo serialise on a shared mutex.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BailiffRepoError> {
        let path = path.as_ref();
        let canonical_path =
            path.canonicalize()
                .map_err(|source| BailiffRepoError::Canonicalize {
                    path: path.to_path_buf(),
                    source,
                })?;
        validate_bare_layout(&canonical_path)?;
        Ok(Self { canonical_path })
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
    pub fn init_or_open(path: impl AsRef<Path>) -> Result<Self, BailiffRepoError> {
        let path = path.as_ref();
        let needs_init = match std::fs::read_dir(path) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(path).map_err(|source| BailiffRepoError::CreateDir {
                    path: path.to_path_buf(),
                    source,
                })?;
                true
            }
            Err(source) => {
                return Err(BailiffRepoError::Io {
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
            )?;
        }
        Self::open(path)
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
    ) -> Result<GitObjectId, BailiffRepoError> {
        // `git notes add -C <oid>` against Git's empty-blob OID
        // (`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`) succeeds without
        // attaching a note, so `write_note` would return a target OID
        // that `read_note` cannot read back. Rejecting empty bodies up
        // front turns the silent gap into a typed error at the only
        // writer.
        if body.is_empty() {
            return Err(BailiffRepoError::EmptyBody);
        }
        let _guard = lock_notes_write(&self.canonical_path);
        let target_oid = hash_object_stdin(&self.canonical_path, seed)?;
        // Write the body as a blob first and reference it via `-C
        // <oid>`. `git notes add -F file` runs the body through
        // `stripspace` (strip trailing whitespace per line, collapse
        // blank lines) which corrupts arbitrary bytes — the envelope
        // is binary in general, so we have to bypass stripspace.
        // `-C <existing_blob_oid>` reuses the object verbatim and is
        // the documented escape hatch.
        let body_oid = hash_object_stdin(&self.canonical_path, body)?;
        // `notes add` creates a commit on the notes ref, so it
        // needs an author identity. The `clean_git` env recipe
        // we run under (HOME=/dev/null, GIT_CONFIG_GLOBAL=/dev/null,
        // GIT_CONFIG_NOSYSTEM=1) deliberately denies git access to
        // every config source except the repo's local file, so we
        // inject the identity via `-c` flags rather than rely on
        // operator gitconfig. The values are placeholders — the
        // commit author is not part of bailiff's audit trail; the
        // signed envelope inside the note body is.
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
        )?;
        Ok(target_oid)
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
    ) -> Result<Vec<u8>, BailiffRepoError> {
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
        )
    }
}

fn validate_bare_layout(path: &Path) -> Result<(), BailiffRepoError> {
    let head = path.join("HEAD");
    if !head.is_file() {
        return Err(BailiffRepoError::MissingHead {
            path: path.to_path_buf(),
        });
    }
    let objects = path.join("objects");
    if !is_dir(&objects) {
        return Err(BailiffRepoError::MissingObjectsDir { path: objects });
    }
    let refs = path.join("refs");
    if !is_dir(&refs) {
        return Err(BailiffRepoError::MissingRefsDir { path: refs });
    }
    // `commondir` at the top level of a worktree points at the shared
    // dir of the parent repo; in a healthy standalone bare repo it
    // does not exist. `symlink_metadata` (lstat) detects the file
    // without following a symlink so a worktree pointing into the
    // repo cannot smuggle itself in as a bare layout.
    let commondir = path.join("commondir");
    match std::fs::symlink_metadata(&commondir) {
        Ok(_) => {
            return Err(BailiffRepoError::Worktree { path: commondir });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BailiffRepoError::Io {
                path: commondir,
                source,
            });
        }
    }
    match git_config_get_bool(path, "core.bare")? {
        Some(true) => {}
        other => return Err(BailiffRepoError::NotBare { value: other }),
    }
    if let Some(fmt) = git_config_get(path, "extensions.objectformat")?
        && fmt != "sha1"
    {
        return Err(BailiffRepoError::UnsupportedObjectFormat { value: fmt });
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
fn prepare_git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
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
) -> Result<Vec<u8>, BailiffRepoError>
where
    I: IntoIterator<Item = &'a str>,
{
    let args: Vec<&str> = args.into_iter().collect();
    let mut command = prepare_git_command(repo);
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
        .map_err(|source| BailiffRepoError::GitSpawn { source })?;

    if let Some(bytes) = stdin_input {
        let mut stdin = child
            .stdin
            .take()
            .expect("stdin was configured as Stdio::piped()");
        stdin
            .write_all(bytes)
            .map_err(|source| BailiffRepoError::GitStdinWrite { source })?;
        drop(stdin);
    }

    let mut stdout_bytes = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_end(&mut stdout_bytes)
            .map_err(|source| BailiffRepoError::GitStdoutRead { source })?;
    }
    let mut stderr_bytes = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut stderr_bytes);
    }

    let status = child
        .wait()
        .map_err(|source| BailiffRepoError::GitWait { source })?;
    if !status.success() {
        return Err(BailiffRepoError::GitFailed {
            args: args.iter().map(|s| (*s).to_string()).collect(),
            status,
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        });
    }
    Ok(stdout_bytes)
}

fn git_config_get_bool(repo: &Path, key: &str) -> Result<Option<bool>, BailiffRepoError> {
    // `--local` is load-bearing: without it, `git config --get`
    // also reads `~/.gitconfig` and the system config, so a global
    // `core.bare = true` would let any directory with HEAD/objects/
    // refs pass validation, and a global `extensions.objectformat =
    // sha256` would reject a valid SHA-1 repo. The layout checks
    // are about the on-disk repo only.
    let output = run_git_config(repo, ["--local", "--bool", "--get", key])?;
    let Some(raw) = output else { return Ok(None) };
    let trimmed = raw.trim();
    match trimmed {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        other => Err(BailiffRepoError::ConfigBoolUnparseable {
            key: key.to_string(),
            got: other.to_string(),
        }),
    }
}

fn git_config_get(repo: &Path, key: &str) -> Result<Option<String>, BailiffRepoError> {
    let output = run_git_config(repo, ["--local", "--get", key])?;
    Ok(output.map(|s| s.trim().to_string()))
}

fn run_git_config<'a>(
    repo: &Path,
    config_args: impl IntoIterator<Item = &'a str>,
) -> Result<Option<String>, BailiffRepoError> {
    let mut command = prepare_git_command(repo);
    command.arg("config");
    for arg in config_args {
        command.arg(arg);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|source| BailiffRepoError::GitSpawn { source })?;
    if output.status.success() {
        let s = String::from_utf8(output.stdout)
            .map_err(|source| BailiffRepoError::ConfigNonUtf8 { source })?;
        Ok(Some(s))
    } else if output.status.code() == Some(1) {
        // Per `git config(1)`, exit code 1 means the key is not set.
        // Any other non-zero exit is an actual error.
        Ok(None)
    } else {
        Err(BailiffRepoError::GitFailed {
            args: vec!["config".to_string()],
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn hash_object_stdin(repo: &Path, bytes: &[u8]) -> Result<GitObjectId, BailiffRepoError> {
    let stdout = run_git(
        repo,
        ["hash-object", "-w", "--stdin"].iter().copied(),
        Some(bytes),
        CaptureOutput::Capture,
    )?;
    let s = String::from_utf8(stdout)
        .map_err(|source| BailiffRepoError::HashObjectNonUtf8 { source })?;
    let trimmed = s.trim();
    GitObjectId::new(trimmed).map_err(|source| BailiffRepoError::HashObjectParse {
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
            // Leaking a `Box<Mutex<()>>` once per distinct bailiff
            // repo gives every handle a `'static` reference to share.
            // The number of distinct repos in a single process is
            // bounded by deployment shape (one bailiff repo today,
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
pub enum BailiffRepoError {
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
    #[error("worktree marker {path:?} present; bailiff requires a standalone bare repo")]
    Worktree { path: PathBuf },
    #[error("repo has core.bare={value:?}, expected core.bare=true")]
    NotBare { value: Option<bool> },
    #[error("repo has extensions.objectformat={value:?}; bailiff only supports sha1")]
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
    use std::fs;
    use tempfile::TempDir;

    fn notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Serialises tests that mutate process environment variables
    /// against tests that invoke `git` directly (without going
    /// through `run_git`, which scrubs the repo-selection env).
    /// Cargo runs tests in parallel by default, so without this the
    /// env pollution window from a "GIT_DIR is ignored" test would
    /// leak into other tests' `Command::new("git")` setups.
    static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn init_or_open_creates_a_bare_repo() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bailiff-repo");
        let repo = BailiffRepo::init_or_open(&path).unwrap();
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
        let a = BailiffRepo::init_or_open(&path).unwrap();
        let b = BailiffRepo::init_or_open(&path).unwrap();
        assert_eq!(a.path(), b.path());
    }

    #[test]
    fn open_rejects_a_plain_directory() {
        let tmp = TempDir::new().unwrap();
        let err = BailiffRepo::open(tmp.path()).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_non_bare_repo() {
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
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
        let err = BailiffRepo::open(&path).unwrap_err();
        // Top-level: no HEAD file at the worktree root.
        assert!(
            matches!(err, BailiffRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
        // Inner `.git`: HEAD exists but core.bare=false.
        let err_inner = BailiffRepo::open(path.join(".git")).unwrap_err();
        assert!(
            matches!(err_inner, BailiffRepoError::NotBare { value: Some(false) }),
            "got: {err_inner:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_head() {
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_file(repo.path().join("HEAD")).unwrap();
        let err = BailiffRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::MissingHead { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_objects() {
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_dir_all(repo.path().join("objects")).unwrap();
        let err = BailiffRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::MissingObjectsDir { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_missing_refs() {
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_dir_all(repo.path().join("refs")).unwrap();
        let err = BailiffRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::MissingRefsDir { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_with_commondir_marker() {
        // Worktrees of another repo have a `commondir` file at their
        // top level pointing at the parent's git dir; bailiff's bare
        // repo never has one. Plant the marker and confirm we reject.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::write(repo.path().join("commondir"), "../some/other/.git\n").unwrap();
        let err = BailiffRepo::open(repo.path()).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::Worktree { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_rejects_repo_with_sha256_object_format() {
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
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
        let err = BailiffRepo::open(&path).unwrap_err();
        assert!(
            matches!(
                err,
                BailiffRepoError::UnsupportedObjectFormat { ref value } if value == "sha256"
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn write_note_round_trips_through_read_note() {
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
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
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
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
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let first = repo.write_note(&nref, b"seed", b"first body").unwrap();
        let err = repo.write_note(&nref, b"seed", b"second body").unwrap_err();
        match err {
            BailiffRepoError::GitFailed { ref args, .. } => {
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
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        // Write *something* under the ref so the ref exists, but ask
        // for a different target — exercises "ref present, no note
        // at this oid" rather than "ref missing entirely".
        let _ = repo.write_note(&nref, b"seed", b"body").unwrap();
        let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
        let err = repo.read_note(&nref, &absent).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::GitFailed { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn notes_under_distinct_refs_do_not_collide() {
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
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
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
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
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let err = repo.write_note(&nref, b"seed", b"").unwrap_err();
        assert!(matches!(err, BailiffRepoError::EmptyBody), "got: {err:?}");
    }

    #[test]
    fn init_or_open_does_not_mutate_existing_non_bare_repo() {
        // Pointing `init_or_open` at the `.git` directory of a real
        // worktree must not run `git init --bare` against it: that
        // would flip core.bare and silently break the worktree. The
        // expected behaviour is to validate-only and surface the
        // mismatch as an open error.
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
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
        let err = BailiffRepo::init_or_open(&git_dir).unwrap_err();
        assert!(
            matches!(err, BailiffRepoError::NotBare { value: Some(false) }),
            "got: {err:?}"
        );
        assert_eq!(fs::read(git_dir.join("HEAD")).unwrap(), head_before);
        assert_eq!(fs::read(git_dir.join("config")).unwrap(), config_before);
    }

    #[test]
    fn write_note_handles_binary_body() {
        // The envelope bytes will not be UTF-8 in general (stdout/stderr
        // are arbitrary bytes). The pipe-to-stdin path must not
        // corrupt non-UTF-8 input.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let body: Vec<u8> = (0u8..=255).collect();
        let target = repo.write_note(&nref, b"seed", &body).unwrap();
        assert_eq!(repo.read_note(&nref, &target).unwrap(), body);
    }

    #[test]
    fn write_note_ignores_parent_git_dir_env() {
        // `git -C <path>` does NOT override an inherited `GIT_DIR`:
        // the env var wins and redirects every git call. Without
        // scrubbing, a parent that exports `GIT_DIR=/elsewhere`
        // would steer `hash-object -w` and `notes add` into the
        // wrong repo. Production code scrubs the repo-selection
        // env in `run_git`; this test sets `GIT_DIR` to an absent
        // path so the un-scrubbed code path would surface as a
        // hash-object failure, while the scrubbed code path
        // succeeds.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let nref = notes_ref();
        let absent_git_dir = tmp.path().join("definitely-not-a-repo");
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
        // SAFETY: set_var/remove_var are unsafe in Rust 2024 because
        // they race with concurrent getenv across threads. The mutex
        // above serialises all tests in this module that touch the
        // process env or invoke `git` directly.
        unsafe {
            std::env::set_var("GIT_DIR", &absent_git_dir);
        }
        let result = repo.write_note(&nref, b"seed", b"body");
        unsafe {
            std::env::remove_var("GIT_DIR");
        }
        let target = result.expect("write_note must ignore parent GIT_DIR");
        assert_eq!(repo.read_note(&nref, &target).unwrap(), b"body");
    }

    #[test]
    fn open_reads_local_config_only_for_core_bare() {
        // Git's config precedence is command-line > env > local >
        // global > system, so a global override only *wins* when
        // local is silent. To exercise the bug, set up a bare repo
        // whose local config is missing the key entirely (delete
        // the file) and plant `core.bare = true` in a fake global.
        // Without `--local`, the lookup falls through to global and
        // returns true — letting a layout-only directory masquerade
        // as a valid bare repo. With `--local`, the lookup returns
        // None and validation fails as `NotBare { value: None }`.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        fs::remove_file(repo.path().join("config")).unwrap();
        let global_cfg = tmp.path().join("globalcfg");
        fs::write(&global_cfg, "[core]\n\tbare = true\n").unwrap();
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_cfg);
        }
        let result = BailiffRepo::open(repo.path());
        unsafe {
            std::env::remove_var("GIT_CONFIG_GLOBAL");
        }
        let err = result.expect_err("open must not honour global core.bare");
        assert!(
            matches!(err, BailiffRepoError::NotBare { value: None }),
            "got: {err:?}"
        );
    }

    #[test]
    fn init_or_open_forces_sha1_against_global_default_hash() {
        // A host with `init.defaultObjectFormat = sha256` in global
        // config would, without an explicit `--object-format=sha1`,
        // produce a SHA-256 bare repo. `open` would then reject it
        // and the first run would fail, leaving an unusable repo on
        // disk. The fix passes the format explicitly; the test
        // pollutes the global to confirm the override holds.
        let tmp = TempDir::new().unwrap();
        let global_cfg = tmp.path().join("globalcfg");
        fs::write(&global_cfg, "[init]\n\tdefaultObjectFormat = sha256\n").unwrap();
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_cfg);
        }
        let result = BailiffRepo::init_or_open(tmp.path().join("r"));
        unsafe {
            std::env::remove_var("GIT_CONFIG_GLOBAL");
        }
        result.expect("init_or_open must force sha1 regardless of global default");
    }

    #[test]
    fn operations_survive_global_safe_bare_repository_explicit() {
        // Hosts that harden Git with `safe.bareRepository = explicit`
        // make implicit `-C <bare-repo>` discovery fail with
        // "cannot use bare repository". The hardened env recipe
        // (env_clear + GIT_CONFIG_GLOBAL=/dev/null) prevents the
        // setting from reaching the child, and `--git-dir=<repo>`
        // sidesteps discovery entirely. Together they keep every
        // op working on a hardened host.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let global_cfg = tmp.path().join("globalcfg");
        fs::write(&global_cfg, "[safe]\n\tbareRepository = explicit\n").unwrap();
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_cfg);
        }
        let open_result = BailiffRepo::open(repo.path());
        let write_result = repo.write_note(&notes_ref(), b"seed", b"body");
        unsafe {
            std::env::remove_var("GIT_CONFIG_GLOBAL");
        }
        open_result.expect("open must survive safe.bareRepository=explicit");
        let target = write_result.expect("write_note must survive same");
        assert_eq!(repo.read_note(&notes_ref(), &target).unwrap(), b"body");
    }

    #[test]
    fn open_reads_local_config_only_for_object_format() {
        // A global `extensions.objectformat = sha256` must not
        // reject a valid SHA-1 repo whose local config is silent.
        let tmp = TempDir::new().unwrap();
        let repo = BailiffRepo::init_or_open(tmp.path().join("r")).unwrap();
        let global_cfg = tmp.path().join("globalcfg");
        fs::write(&global_cfg, "[extensions]\n\tobjectformat = sha256\n").unwrap();
        let _env_guard = ENV_TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_cfg);
        }
        let result = BailiffRepo::open(repo.path());
        unsafe {
            std::env::remove_var("GIT_CONFIG_GLOBAL");
        }
        result.expect("open must read --local extensions.objectformat, not global");
    }
}
