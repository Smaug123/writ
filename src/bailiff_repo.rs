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
//! `env_clear`, only the four `CLEAN_GIT_CONFIG_*` / `HOME=/dev/null`
//! variables set, `cwd=/` so a stray config in the broker's working
//! directory cannot override anything. Operations on bailiff's repo
//! are local, sub-second, and trusted, so we don't replicate
//! `clean_git`'s timeout + process-group SIGKILL machinery — git
//! exiting cleanly is the supervisor here, and any hang would itself
//! be a higher-priority bug than the things that harness is built to
//! contain.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::vm_git::{GitObjectId, GitObjectIdError};

use crate::core::NotesRef;

/// A handle to bailiff's bare Git repository on the local filesystem.
///
/// Construct via [`BailiffRepo::open`] (validates an existing bare
/// repo) or [`BailiffRepo::init_or_open`] (creates one on first run
/// then opens it). Cloning is cheap — the type is just a `PathBuf`
/// alongside a "this passed validation" marker.
#[derive(Clone, Debug)]
pub struct BailiffRepo {
    path: PathBuf,
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
    /// Returns [`BailiffRepoError::NotABareRepo`] for any of the
    /// above failing — the operator's "I pointed writ at the wrong
    /// directory" path produces one typed error, not a grab-bag of
    /// I/O surprises.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, BailiffRepoError> {
        let path = path.into();
        validate_bare_repo(&path).await?;
        Ok(Self { path })
    }

    /// Open an existing bare repo at `path`, or create one there if
    /// the directory has no `HEAD` yet. Idempotent: the second call
    /// for the same path is a pure open. Equivalent to
    /// `git init --bare <path>` followed by [`open`](Self::open).
    pub async fn init_or_open(path: impl Into<PathBuf>) -> Result<Self, BailiffRepoError> {
        let path = path.into();
        // `git init --bare` is itself idempotent — running it on an
        // existing bare repo is a no-op for the on-disk state — but
        // calling it unconditionally would also mean creating any
        // missing parent directories git would create on first run,
        // which we'd rather not do silently. So: only init if HEAD
        // is missing; then open the result either way, which is what
        // applies the bare-repo validation.
        let head_path = path.join("HEAD");
        if !head_path.exists() {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(BailiffRepoError::Io)?;
            }
            run_git_status(
                &[OsStr::new("init"), OsStr::new("--bare"), path.as_os_str()],
                None,
            )
            .await?;
        }
        Self::open(path).await
    }

    /// Write `bytes` as a loose Git blob into this repo and return
    /// the resulting object id. Wraps `git -C <path> hash-object -w
    /// --stdin`: identical bytes always produce the same OID (Git's
    /// content-addressing), so calling this twice for the same
    /// payload is harmless and returns the same value.
    pub async fn write_blob(&self, bytes: &[u8]) -> Result<GitObjectId, BailiffRepoError> {
        let stdout = run_git_capture_stdout(
            &[
                OsStr::new("-C"),
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
        // Detect existing note up-front so we can return the typed
        // `NoteAlreadyExists` rather than the generic GitFailed that
        // `git notes add` (without `-f`) produces. The two-step shape
        // is also what lets us keep the write itself force-free.
        if note_exists(&self.path, notes_ref, target).await? {
            return Err(BailiffRepoError::NoteAlreadyExists {
                notes_ref: notes_ref.as_str().to_string(),
                target: target.as_str().to_string(),
            });
        }
        let ref_arg = format!("--ref={}", notes_ref.as_str());
        run_git_status(
            &[
                OsStr::new("-C"),
                self.path.as_os_str(),
                OsStr::new("notes"),
                OsStr::new(&ref_arg),
                OsStr::new("add"),
                OsStr::new("-F"),
                OsStr::new("-"),
                OsStr::new(target.as_str()),
            ],
            Some(body),
        )
        .await
    }
}

/// Check whether a note currently exists at `(notes_ref, target)`.
/// Implementation detail of `write_note` — `git notes list <target>`
/// exits 0 with the note OID on stdout when one exists, exits 1
/// when no note exists. Treat any other non-zero exit as a real
/// git failure rather than absence.
async fn note_exists(
    repo: &Path,
    notes_ref: &NotesRef,
    target: &GitObjectId,
) -> Result<bool, BailiffRepoError> {
    let ref_arg = format!("--ref={}", notes_ref.as_str());
    let outcome = run_git(
        &[
            OsStr::new("-C"),
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
    Ok(())
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
    args: &[&OsStr],
    stdin_via: Option<&[u8]>,
    capture_stdout: bool,
) -> Result<GitOutcome, BailiffRepoError> {
    let mut command = Command::new("git");
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
async fn run_git_status(args: &[&OsStr], stdin_via: Option<&[u8]>) -> Result<(), BailiffRepoError> {
    let label = describe_args(args);
    let outcome = run_git(args, stdin_via, false).await?;
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
    args: &[&OsStr],
    stdin_via: Option<&[u8]>,
) -> Result<Vec<u8>, BailiffRepoError> {
    let label = describe_args(args);
    let outcome = run_git(args, stdin_via, true).await?;
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
const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 4] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("HOME", "/dev/null"),
];

/// Run git from `/` so a stray `.git/config` in whatever directory
/// writ happens to be launched from cannot rewrite anything.
const CLEAN_GIT_CURRENT_DIR: &str = "/";

#[derive(Debug, thiserror::Error)]
pub enum BailiffRepoError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
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

    /// `init_or_open` on a fresh empty directory must produce a
    /// bare repo: HEAD + `core.bare = true`.
    #[tokio::test]
    async fn init_or_open_creates_a_bare_repo() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path().join("bailiff-repo");
        let repo = BailiffRepo::init_or_open(&repo_path).await.unwrap();
        assert_eq!(repo.path(), repo_path);
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
        run_git_status(
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

        let stdout = run_git_capture_stdout(
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

        let ref_arg = format!("--ref={}", r.as_str());
        let stdout = run_git_capture_stdout(
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
        // `git notes show` emits the note body followed by a single
        // trailing newline.
        let trimmed = stdout.strip_suffix(b"\n").unwrap_or(&stdout);
        assert_eq!(trimmed, b"note body for that payload");
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
        let ref_arg = format!("--ref={}", r.as_str());
        let stdout = run_git_capture_stdout(
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
        let trimmed = stdout.strip_suffix(b"\n").unwrap_or(&stdout);
        assert_eq!(trimmed, b"first");
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
        // Both notes are independently retrievable.
        for (r, body) in [(&r1, b"under a".as_slice()), (&r2, b"under b".as_slice())] {
            let ref_arg = format!("--ref={}", r.as_str());
            let stdout = run_git_capture_stdout(
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
            assert_eq!(stdout.strip_suffix(b"\n").unwrap_or(&stdout), body);
        }
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
}
