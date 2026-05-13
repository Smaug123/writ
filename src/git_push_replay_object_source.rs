//! Production [`GitObjectSource`] backed by a long-lived
//! `git cat-file --batch` subprocess against the staging repo.
//!
//! Each [`CatFileObjectSource`] owns one child. Trait calls serialise
//! through an interior [`tokio::sync::Mutex`] so the request/response
//! framing on the child's pipes is never interleaved between
//! concurrent callers. The walker uses this source serially in
//! practice, but the trait gives `&self`, so the mutex is the only
//! way to keep the framing invariant locally checkable.
//!
//! ## Functional core
//!
//! The bytes-to-objects translation lives in
//! [`parse_commit_object`] and [`parse_tree_object`] — pure functions
//! over `&[u8]` so property tests can drive them without any I/O.
//! Their inverses [`serialize_commit_object`] and
//! [`serialize_tree_object`] are also pub-crate; the orchestrator's
//! hash-equivalence oracle reconstructs canonical git bytes from the
//! same data the walker would upload, and the round-trip property
//! `parse(serialize(x)) == x` rules out drift between the two.
//!
//! ## Cat-file batch protocol
//!
//! `git cat-file --batch` reads SHA-per-line requests on stdin and
//! emits one of:
//!
//! * `<sha> SP <type> SP <size> LF` followed by exactly `<size>` raw
//!   bytes and a single trailing LF, when the object exists.
//! * `<sha> SP missing LF` when the SHA is not in the object
//!   database.
//! * `<sha> SP ambiguous LF` when an abbreviated SHA matches more
//!   than one object. We never pass abbreviated SHAs so this is
//!   treated as a malformed response rather than a normal case.
//!
//! ## Cancellation
//!
//! Dropping a future that is partway through `read_*` while the
//! child is mid-response leaves the framing out of sync: the next
//! request would read the leftover bytes as a response header. We
//! do not attempt to recover; the walker runs to completion before
//! the source is dropped, and a cancellation in that path indicates
//! a bug elsewhere. The mutex guard releases on cancel, so the type
//! is sound — just unusable thereafter.

use std::ffi::OsString;
use std::io;
use std::num::ParseIntError;
use std::path::Path;
use std::process::Stdio;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::clean_git::{self, CLEAN_GIT_CONFIG_ENV, CLEAN_GIT_CURRENT_DIR, CleanGitError};
use crate::git_push_replay_walker::{
    GitObjectSource, GitObjectSourceError, StagingCommit, StagingTree, StagingTreeEntry,
};
use crate::github_git_db::{CommitIdentity, TreeEntryKind};
use crate::process_spawn;
use crate::vm_git::{GitObjectId, GitObjectIdError};

/// `git cat-file --batch` instance bound to a staging repository.
pub struct CatFileObjectSource {
    /// Process group id of the cat-file leader. The child is spawned
    /// with `process_group(0)`, so this equals the leader's pid and is
    /// inherited by any helper the leader forks (or by anything inside
    /// the configured `git_program` if it is a wrapper script). Stored
    /// at the top level so [`Drop`] can `killpg` the whole group
    /// without needing access to the child through the mutex.
    pgid: libc::pid_t,
    /// `None` once [`close`](Self::close) has consumed the child. Drop
    /// uses this discriminator to decide whether to send SIGKILL: a
    /// clean close should not kill, because the leader has already
    /// exited and its pid may have been recycled by an unrelated
    /// process by the time the source falls out of scope.
    inner: Option<Mutex<CatFileChild>>,
}

struct CatFileChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The `git` program could not be located or canonicalized under
    /// the same rules the rest of the replay pipeline uses. The
    /// underlying [`CleanGitError`] is stringified to keep the
    /// hardening module's variants out of the public surface.
    #[error("could not resolve git program: {0}")]
    GitProgram(String),
    #[error("could not spawn `git cat-file --batch`: {0}")]
    Spawn(#[source] io::Error),
    #[error("`git cat-file --batch` child did not expose a pid")]
    MissingProcessId,
    #[error("`git cat-file --batch` child pid {0} does not fit in pid_t")]
    InvalidProcessId(u32),
    #[error("`git cat-file --batch` child did not expose stdin")]
    MissingStdin,
    #[error("`git cat-file --batch` child did not expose stdout")]
    MissingStdout,
}

impl From<CleanGitError> for OpenError {
    fn from(err: CleanGitError) -> Self {
        OpenError::GitProgram(err.to_string())
    }
}

impl CatFileObjectSource {
    /// Spawn `git -C <staging_repo> cat-file --batch` under the
    /// hardened clean-Git environment.
    ///
    /// The child runs from `/`, has its environment cleared down to
    /// the four [`CLEAN_GIT_CONFIG_ENV`] entries, and is placed in a
    /// fresh process group so a runaway helper cannot outlive its
    /// leader. The source's [`Drop`] impl sends SIGKILL to the
    /// *process group* (`killpg`), not just the leader pid; this is
    /// the only thing that catches a helper Git forks (or anything a
    /// wrapper script behind `git_program` spawns) before the source
    /// is dropped. `kill_on_drop(true)` is left on so tokio reaps the
    /// leader after our `killpg` runs and avoids a zombie.
    pub async fn open(staging_repo: &Path, git_program: &Path) -> Result<Self, OpenError> {
        let program = clean_git::resolve_program_for_clean_env(git_program).await?;
        let mut command = Command::new(&program);
        command.env_clear();
        for (name, value) in CLEAN_GIT_CONFIG_ENV {
            command.env(name, value);
        }
        command.args([
            OsString::from("-C"),
            staging_repo.as_os_str().to_os_string(),
            OsString::from("cat-file"),
            OsString::from("--batch"),
        ]);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::null());
        command.current_dir(CLEAN_GIT_CURRENT_DIR);
        command.process_group(0);
        // Reap the leader after our `killpg` runs in Drop, so a
        // forgotten `close()` cannot leak a zombie cat-file.
        command.kill_on_drop(true);

        let mut child = process_spawn::spawn_async(&mut command)
            .await
            .map_err(OpenError::Spawn)?;
        let pid = child.id().ok_or(OpenError::MissingProcessId)?;
        let pgid: libc::pid_t = pid
            .try_into()
            .map_err(|_| OpenError::InvalidProcessId(pid))?;
        let stdin = child.stdin.take().ok_or(OpenError::MissingStdin)?;
        let stdout = child.stdout.take().ok_or(OpenError::MissingStdout)?;
        Ok(Self {
            pgid,
            inner: Some(Mutex::new(CatFileChild {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            })),
        })
    }

    /// Close the child gracefully: drop stdin to signal EOF, then
    /// `wait()` the cat-file process to completion. Returns the
    /// exit status as an error if the child exited non-zero.
    ///
    /// Cancellation safety: from the moment we take ownership of
    /// the child the source's outer [`Drop`] is disarmed (`inner`
    /// is `None`), so a local [`PgidCleanupGuard`] takes over and
    /// SIGKILLs the process group if anything between here and the
    /// final `disarm()` panics or has its await cancelled. After
    /// the leader is reaped we then `killpg` to mop up any helper
    /// that was sharing the group (a wrapper script's children,
    /// say) before disarming the guard.
    pub async fn close(mut self) -> io::Result<()> {
        let pgid = self.pgid;
        let mutex = self
            .inner
            .take()
            .expect("CatFileObjectSource::inner is always Some until close consumes it");
        let mut guard = PgidCleanupGuard::new(pgid);
        let CatFileChild {
            mut child,
            stdin,
            stdout,
        } = mutex.into_inner();
        drop(stdin);
        drop(stdout);
        let wait_result = child.wait().await;
        // wait() reaped the leader (or failed). Either way, kill
        // any helpers still in the group before the guard would
        // otherwise have to do it. We tolerate ESRCH (group is
        // already gone) and EPERM (macOS race after the leader is
        // reaped): both mean there is nothing left to signal.
        kill_process_group_best_effort(pgid)?;
        guard.disarm();
        let status = wait_result?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "`git cat-file --batch` exited with non-zero status: {status}"
            )));
        }
        Ok(())
    }
}

impl Drop for CatFileObjectSource {
    fn drop(&mut self) {
        // `close()` clears `inner` on its successful path. Anything
        // else — Drop without `close()`, a cancelled future before
        // `close()` even started, or a panic — means the source
        // still owns the child and the process group might contain
        // live helpers. SIGKILL the group so nothing outlives the
        // source. Errors are intentionally swallowed: there is
        // nothing useful to do with them from Drop, and ESRCH (the
        // group is already gone) is a normal race.
        if self.inner.is_some() {
            unsafe { libc::killpg(self.pgid, libc::SIGKILL) };
        }
    }
}

/// RAII guard that SIGKILLs a process group on drop unless
/// explicitly disarmed. Used inside [`CatFileObjectSource::close`]
/// to keep the kill scheduled across `await` points so a future
/// cancellation or panic still cleans the group up.
struct PgidCleanupGuard {
    pgid: libc::pid_t,
    armed: bool,
}

impl PgidCleanupGuard {
    fn new(pgid: libc::pid_t) -> Self {
        Self { pgid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PgidCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            unsafe { libc::killpg(self.pgid, libc::SIGKILL) };
        }
    }
}

fn kill_process_group_best_effort(pgid: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // No such process group: somebody already cleaned up.
        Some(libc::ESRCH) => Ok(()),
        // macOS reports EPERM once the leader has been reaped and
        // no signalable members remain; treat as success.
        Some(libc::EPERM) => Ok(()),
        _ => Err(err),
    }
}

impl CatFileObjectSource {
    fn child_mutex(&self) -> &Mutex<CatFileChild> {
        self.inner
            .as_ref()
            .expect("inner is always Some between open and close")
    }
}

impl GitObjectSource for CatFileObjectSource {
    async fn read_commit(&self, sha: &GitObjectId) -> Result<StagingCommit, GitObjectSourceError> {
        let raw = read_object_raw(self.child_mutex(), sha, "commit").await?;
        parse_commit_object(&raw).map_err(|reason| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: reason.to_string(),
        })
    }

    async fn read_tree(&self, sha: &GitObjectId) -> Result<StagingTree, GitObjectSourceError> {
        let raw = read_object_raw(self.child_mutex(), sha, "tree").await?;
        parse_tree_object(&raw).map_err(|reason| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: reason.to_string(),
        })
    }

    async fn read_blob(&self, sha: &GitObjectId) -> Result<Vec<u8>, GitObjectSourceError> {
        read_object_raw(self.child_mutex(), sha, "blob").await
    }
}

async fn read_object_raw(
    inner: &Mutex<CatFileChild>,
    sha: &GitObjectId,
    expected_type: &str,
) -> Result<Vec<u8>, GitObjectSourceError> {
    let mut guard = inner.lock().await;
    let child = &mut *guard;

    let request = format!("{}\n", sha.as_str());
    child
        .stdin
        .write_all(request.as_bytes())
        .await
        .map_err(|source| GitObjectSourceError::Io { source })?;
    child
        .stdin
        .flush()
        .await
        .map_err(|source| GitObjectSourceError::Io { source })?;

    let mut header = String::new();
    let read = child
        .stdout
        .read_line(&mut header)
        .await
        .map_err(|source| GitObjectSourceError::Io { source })?;
    if read == 0 {
        return Err(GitObjectSourceError::Io {
            source: io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "`git cat-file --batch` closed stdout before responding",
            ),
        });
    }
    if !header.ends_with('\n') {
        return Err(GitObjectSourceError::Io {
            source: io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "`git cat-file --batch` response header is not LF-terminated",
            ),
        });
    }
    header.pop();

    let mut fields = header.split(' ');
    let _echoed_sha = fields
        .next()
        .ok_or_else(|| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!("empty cat-file response: {header:?}"),
        })?;
    let kind_field = fields
        .next()
        .ok_or_else(|| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!("cat-file response missing type field: {header:?}"),
        })?;
    // `missing` and `ambiguous` carry no payload, so we can return
    // immediately without disturbing the pipe framing.
    match kind_field {
        "missing" => {
            return Err(GitObjectSourceError::NotFound {
                sha: sha.as_str().to_string(),
            });
        }
        "ambiguous" => {
            return Err(GitObjectSourceError::Malformed {
                sha: sha.as_str().to_string(),
                reason: "cat-file reported the SHA as ambiguous".to_string(),
            });
        }
        _ => {}
    }
    let size_field = fields
        .next()
        .ok_or_else(|| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!("cat-file response missing size field: {header:?}"),
        })?;
    if fields.next().is_some() {
        return Err(GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!("cat-file response has trailing junk: {header:?}"),
        });
    }
    let size: usize =
        size_field
            .parse()
            .map_err(|err: ParseIntError| GitObjectSourceError::Malformed {
                sha: sha.as_str().to_string(),
                reason: format!("cat-file size field {size_field:?} is not a usize: {err}"),
            })?;

    // Drain the full payload (size bytes + trailing LF) before
    // applying the type check. Returning early on a type mismatch
    // without consuming the body would leave the next caller's
    // read_* framed against the tail of this object's bytes,
    // silently corrupting every subsequent read.
    let mut payload = vec![0u8; size];
    child
        .stdout
        .read_exact(&mut payload)
        .await
        .map_err(|source| GitObjectSourceError::Io { source })?;
    let mut trailing = [0u8; 1];
    child
        .stdout
        .read_exact(&mut trailing)
        .await
        .map_err(|source| GitObjectSourceError::Io { source })?;
    if trailing[0] != b'\n' {
        return Err(GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!(
                "cat-file payload not LF-terminated: trailing byte 0x{:02x}",
                trailing[0]
            ),
        });
    }
    if kind_field != expected_type {
        return Err(GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: format!("expected `{expected_type}`, got `{kind_field}`"),
        });
    }
    Ok(payload)
}

// =============== Functional core: parsers and serializers ==================

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseObjectError {
    #[error("unterminated header line in commit object")]
    UnterminatedHeader,
    #[error("commit object truncated before blank line / body")]
    Truncated,
    #[error("commit header line {0:?} is malformed (no SP separator)")]
    MalformedHeader(String),
    #[error("commit has duplicate `{0}` header")]
    DuplicateHeader(&'static str),
    #[error("commit is missing required `{0}` header")]
    MissingHeader(&'static str),
    #[error("commit header SHA in `{key}` line is not a valid object id: {source}")]
    InvalidHeaderSha {
        key: &'static str,
        #[source]
        source: GitObjectIdError,
    },
    #[error("identity line is not valid UTF-8: {0}")]
    NonUtf8Identity(#[source] std::str::Utf8Error),
    #[error("identity line is malformed: {0}")]
    MalformedIdentity(String),
    #[error("commit message is not valid UTF-8: {0}")]
    NonUtf8Message(#[source] std::str::Utf8Error),
    #[error("tree entry header is malformed: {0}")]
    MalformedTreeEntry(String),
    #[error("tree entry mode {0:?} is not recognized")]
    UnknownTreeMode(String),
    #[error("tree entry path is not valid UTF-8: {0}")]
    NonUtf8TreePath(#[source] std::str::Utf8Error),
    #[error("tree entry SHA is invalid: {0}")]
    InvalidTreeSha(#[source] GitObjectIdError),
}

/// Parse the raw bytes of a git commit object into a [`StagingCommit`].
///
/// Accepts the canonical on-disk format (the same bytes
/// `git cat-file --batch` and `git hash-object -t commit --stdin`
/// produce / consume). Unknown headers — notably `gpgsig` with its
/// continuation lines — are skipped, since the walker re-signs (or
/// leaves unsigned) commits on the App side.
pub(crate) fn parse_commit_object(bytes: &[u8]) -> Result<StagingCommit, ParseObjectError> {
    let mut tree: Option<GitObjectId> = None;
    let mut parents: Vec<GitObjectId> = Vec::new();
    let mut author: Option<CommitIdentity> = None;
    let mut committer: Option<CommitIdentity> = None;

    let mut cursor = 0;
    loop {
        if cursor >= bytes.len() {
            return Err(ParseObjectError::Truncated);
        }
        if bytes[cursor] == b'\n' {
            cursor += 1;
            break;
        }
        let header_start = cursor;
        let header_end =
            find_byte(bytes, b'\n', header_start).ok_or(ParseObjectError::UnterminatedHeader)?;
        cursor = header_end + 1;
        // Absorb continuation lines (a leading SP marks a folded
        // continuation; we discard the value since we never use
        // multi-line headers).
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            let next_lf =
                find_byte(bytes, b'\n', cursor).ok_or(ParseObjectError::UnterminatedHeader)?;
            cursor = next_lf + 1;
        }

        let header_line = &bytes[header_start..header_end];
        let sp = header_line.iter().position(|b| *b == b' ').ok_or_else(|| {
            ParseObjectError::MalformedHeader(String::from_utf8_lossy(header_line).into_owned())
        })?;
        let key = &header_line[..sp];
        let value = &header_line[sp + 1..];
        match key {
            b"tree" => {
                if tree.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("tree"));
                }
                tree = Some(parse_sha(value, "tree")?);
            }
            b"parent" => parents.push(parse_sha(value, "parent")?),
            b"author" => {
                if author.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("author"));
                }
                author = Some(parse_identity(value)?);
            }
            b"committer" => {
                if committer.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("committer"));
                }
                committer = Some(parse_identity(value)?);
            }
            _ => {
                // Unknown header (gpgsig, mergetag, encoding, etc.).
                // Skip it: replay never preserves arbitrary headers.
            }
        }
    }

    let tree = tree.ok_or(ParseObjectError::MissingHeader("tree"))?;
    let author = author.ok_or(ParseObjectError::MissingHeader("author"))?;
    let committer = committer.ok_or(ParseObjectError::MissingHeader("committer"))?;
    let message_bytes = &bytes[cursor..];
    let message = std::str::from_utf8(message_bytes)
        .map_err(ParseObjectError::NonUtf8Message)?
        .to_string();

    Ok(StagingCommit {
        tree,
        parents,
        author,
        committer,
        message,
    })
}

/// Reverse of [`parse_commit_object`].
///
/// Emits headers in the order `tree`, then each `parent` in slot
/// order, then `author`, then `committer`, then a blank line, then
/// the message bytes verbatim. The output is the canonical git
/// commit format git itself emits — no signature, no encoding
/// directive — so `git hash-object -t commit --stdin` over these
/// bytes returns the SHA git would assign to a commit holding this
/// `StagingCommit`'s data.
///
/// Used by the dry-run orchestrator's hash-equivalence oracle in
/// a follow-up slice; until then it is exercised exclusively by
/// the parser round-trip property test.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn serialize_commit_object(commit: &StagingCommit) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"tree ");
    out.extend_from_slice(commit.tree.as_str().as_bytes());
    out.push(b'\n');
    for parent in &commit.parents {
        out.extend_from_slice(b"parent ");
        out.extend_from_slice(parent.as_str().as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"author ");
    out.extend_from_slice(serialize_identity(&commit.author).as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"committer ");
    out.extend_from_slice(serialize_identity(&commit.committer).as_bytes());
    out.push(b'\n');
    out.push(b'\n');
    out.extend_from_slice(commit.message.as_bytes());
    out
}

/// Parse the raw bytes of a git tree object into a [`StagingTree`].
///
/// Each entry is `<mode> SP <path> NUL <20-raw-byte-sha>`, with no
/// separator between entries.
pub(crate) fn parse_tree_object(bytes: &[u8]) -> Result<StagingTree, ParseObjectError> {
    let mut entries = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let sp = bytes[cursor..]
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| {
                ParseObjectError::MalformedTreeEntry("missing SP between mode and path".to_string())
            })?;
        let mode_bytes = &bytes[cursor..cursor + sp];
        let mode_str = std::str::from_utf8(mode_bytes).map_err(|_| {
            ParseObjectError::MalformedTreeEntry(format!("tree mode is not ASCII: {mode_bytes:?}"))
        })?;
        let kind = parse_tree_entry_kind(mode_str)?;
        cursor += sp + 1;

        let nul = bytes[cursor..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| {
                ParseObjectError::MalformedTreeEntry(
                    "missing NUL after tree entry path".to_string(),
                )
            })?;
        let path_bytes = &bytes[cursor..cursor + nul];
        let path = std::str::from_utf8(path_bytes)
            .map_err(ParseObjectError::NonUtf8TreePath)?
            .to_string();
        cursor += nul + 1;

        if cursor + 20 > bytes.len() {
            return Err(ParseObjectError::MalformedTreeEntry(
                "tree entry truncated before 20-byte SHA".to_string(),
            ));
        }
        let sha_bytes = &bytes[cursor..cursor + 20];
        let sha =
            GitObjectId::new(hex_encode(sha_bytes)).map_err(ParseObjectError::InvalidTreeSha)?;
        cursor += 20;

        entries.push(StagingTreeEntry { path, kind, sha });
    }
    Ok(StagingTree { entries })
}

/// Reverse of [`parse_tree_object`]. Emits each entry in the order
/// supplied by the caller, using the canonical (leading-zero-stripped)
/// mode for subtrees.
///
/// See the dead-code note on [`serialize_commit_object`].
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn serialize_tree_object(tree: &StagingTree) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in &tree.entries {
        out.extend_from_slice(canonical_tree_mode(entry.kind).as_bytes());
        out.push(b' ');
        out.extend_from_slice(entry.path.as_bytes());
        out.push(0);
        out.extend_from_slice(&hex_decode(entry.sha.as_str()));
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
fn canonical_tree_mode(kind: TreeEntryKind) -> &'static str {
    // Tree-object on-disk modes omit the leading zero for
    // directories (40000), matching what `git hash-object` emits.
    // Other modes carry their full 6 digits.
    match kind {
        TreeEntryKind::Blob => "100644",
        TreeEntryKind::Executable => "100755",
        TreeEntryKind::Symlink => "120000",
        TreeEntryKind::Subtree => "40000",
        TreeEntryKind::Submodule => "160000",
    }
}

fn parse_tree_entry_kind(mode: &str) -> Result<TreeEntryKind, ParseObjectError> {
    match mode {
        "100644" => Ok(TreeEntryKind::Blob),
        "100755" => Ok(TreeEntryKind::Executable),
        "120000" => Ok(TreeEntryKind::Symlink),
        // Accept both shapes for subtrees: on-disk the leading zero
        // is stripped, but some tools (and historical bundles) emit
        // the padded form.
        "40000" | "040000" => Ok(TreeEntryKind::Subtree),
        "160000" => Ok(TreeEntryKind::Submodule),
        other => Err(ParseObjectError::UnknownTreeMode(other.to_string())),
    }
}

fn parse_sha(value: &[u8], key: &'static str) -> Result<GitObjectId, ParseObjectError> {
    let text = std::str::from_utf8(value).map_err(|_| {
        ParseObjectError::MalformedHeader(format!("`{key}` header value is not ASCII: {value:?}"))
    })?;
    GitObjectId::new(text).map_err(|source| ParseObjectError::InvalidHeaderSha { key, source })
}

fn parse_identity(value: &[u8]) -> Result<CommitIdentity, ParseObjectError> {
    let text = std::str::from_utf8(value).map_err(ParseObjectError::NonUtf8Identity)?;
    let (rest, tz_str) = text.rsplit_once(' ').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity {text:?} has no timezone field"))
    })?;
    let (name_email, seconds_str) = rest.rsplit_once(' ').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity {text:?} has no seconds field"))
    })?;
    let (name, email) = parse_name_email(name_email)?;
    let seconds: i64 = seconds_str.parse().map_err(|err: ParseIntError| {
        ParseObjectError::MalformedIdentity(format!(
            "identity seconds field {seconds_str:?} is not an i64: {err}"
        ))
    })?;
    let offset = parse_tz_offset(tz_str)?;
    let date = OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|err| {
            ParseObjectError::MalformedIdentity(format!(
                "unix timestamp {seconds} is out of range: {err}"
            ))
        })?
        .to_offset(offset);
    CommitIdentity::new(name, email, date).map_err(|err| {
        ParseObjectError::MalformedIdentity(format!("could not build identity: {err}"))
    })
}

fn parse_name_email(s: &str) -> Result<(&str, &str), ParseObjectError> {
    if !s.ends_with('>') {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity name<email> does not end with `>`: {s:?}"
        )));
    }
    let inner = &s[..s.len() - 1];
    let lt = inner.rfind('<').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity name<email> is missing `<`: {s:?}"))
    })?;
    let name_end = if lt > 0 && inner.as_bytes()[lt - 1] == b' ' {
        lt - 1
    } else {
        lt
    };
    let name = &inner[..name_end];
    let email = &inner[lt + 1..];
    Ok((name, email))
}

fn parse_tz_offset(s: &str) -> Result<time::UtcOffset, ParseObjectError> {
    // The staging repo is untrusted, so a commit object can carry
    // arbitrary UTF-8 in the timezone slot. `s.len()` counts bytes,
    // but `s[1..3]` on a string with a multibyte character (e.g.
    // `+1é2` — 5 bytes, 4 chars) would slice across a UTF-8
    // boundary and panic. Operate on the byte array and verify
    // each digit position is ASCII before any numeric parse.
    let bytes = s.as_bytes();
    if bytes.len() != 5 {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "timezone field {s:?} must be ±HHMM"
        )));
    }
    let sign: i32 = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => {
            return Err(ParseObjectError::MalformedIdentity(format!(
                "timezone field {s:?} must start with `+` or `-`"
            )));
        }
    };
    let hours = parse_two_ascii_digits(&bytes[1..3]).ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone hours field in {s:?} is not 2 ASCII digits"
        ))
    })?;
    let minutes = parse_two_ascii_digits(&bytes[3..5]).ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone minutes field in {s:?} is not 2 ASCII digits"
        ))
    })?;
    let total = sign * (i32::from(hours) * 3600 + i32::from(minutes) * 60);
    time::UtcOffset::from_whole_seconds(total).map_err(|err| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone field {s:?} resolves to invalid offset: {err}"
        ))
    })
}

fn parse_two_ascii_digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

#[cfg_attr(not(test), allow(dead_code))]
fn serialize_identity(identity: &CommitIdentity) -> String {
    // CommitIdentity guarantees the stored RFC3339 string round-trips
    // through `time::OffsetDateTime::parse` — the constructor was the
    // formatter that produced it. The `expect` here pins that
    // invariant: a failure would mean someone removed the constructor's
    // validation, not bad input.
    let dt = OffsetDateTime::parse(identity.date_rfc3339(), &Rfc3339)
        .expect("CommitIdentity stores RFC3339 produced by `time` itself");
    let seconds = dt.unix_timestamp();
    let offset_seconds = dt.offset().whole_seconds();
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs_seconds = offset_seconds.unsigned_abs();
    let hours = abs_seconds / 3600;
    let minutes = (abs_seconds % 3600) / 60;
    format!(
        "{} <{}> {} {}{:02}{:02}",
        identity.name(),
        identity.email(),
        seconds,
        sign,
        hours,
        minutes,
    )
}

fn find_byte(haystack: &[u8], needle: u8, from: usize) -> Option<usize> {
    haystack[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|i| i + from)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing into String never fails");
    }
    s
}

#[cfg_attr(not(test), allow(dead_code))]
fn hex_decode(hex: &str) -> Vec<u8> {
    debug_assert_eq!(hex.len() % 2, 0, "GitObjectId is always even-length hex");
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
fn hex_nibble(byte: u8) -> u8 {
    // GitObjectId validates hex on construction, so we only ever
    // see ASCII hex bytes here.
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("GitObjectId invariant violated: non-hex byte {byte}"),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command as StdCommand;

    use proptest::collection::vec as prop_vec;
    use proptest::prelude::*;
    use time::macros::datetime;

    use super::*;

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn sample_identity(name: &str) -> CommitIdentity {
        CommitIdentity::new(
            name,
            format!("{name}@example.invalid"),
            datetime!(2024-01-15 10:30:45 UTC),
        )
        .expect("sample date formats")
    }

    // ============== Parser unit tests ==============

    #[test]
    fn parse_commit_object_minimal_round_trip() {
        let commit = StagingCommit {
            tree: sample_object_id('a'),
            parents: vec![sample_object_id('b'), sample_object_id('c')],
            author: sample_identity("Alice"),
            committer: sample_identity("Bob"),
            message: "first line\n\nbody\n".to_string(),
        };
        let bytes = serialize_commit_object(&commit);
        let parsed = parse_commit_object(&bytes).expect("round-trip parse");
        assert_eq!(parsed, commit);
    }

    #[test]
    fn parse_commit_object_skips_unknown_headers() {
        let commit = StagingCommit {
            tree: sample_object_id('a'),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bob"),
            message: "x\n".to_string(),
        };
        // Inject a gpgsig-style folded header between committer and
        // the blank line. The parser must absorb it without
        // disturbing the surrounding fields.
        let mut bytes = serialize_commit_object(&commit);
        let blank_pos = bytes
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("commit always has a blank line before the body");
        let injection = b"gpgsig -----BEGIN PGP SIGNATURE-----\n garbage continuation\n -----END PGP SIGNATURE-----\n";
        bytes.splice(blank_pos + 1..blank_pos + 1, injection.iter().copied());

        let parsed = parse_commit_object(&bytes).expect("parser should skip unknown headers");
        assert_eq!(parsed, commit);
    }

    #[test]
    fn parse_commit_object_rejects_duplicate_tree() {
        let mut commit = StagingCommit {
            tree: sample_object_id('a'),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bob"),
            message: "x\n".to_string(),
        };
        let mut bytes = serialize_commit_object(&commit);
        commit.tree = sample_object_id('d');
        let dup = format!("tree {}\n", commit.tree.as_str());
        bytes.splice(0..0, dup.bytes());
        let err = parse_commit_object(&bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::DuplicateHeader("tree")),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_commit_object_rejects_missing_tree() {
        let bytes = b"author Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nmsg";
        let err = parse_commit_object(bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::MissingHeader("tree")),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_commit_object_rejects_truncated_before_blank() {
        let bytes = b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let err = parse_commit_object(bytes).unwrap_err();
        assert!(matches!(err, ParseObjectError::Truncated), "got: {err:?}");
    }

    #[test]
    fn parse_tree_object_round_trip_mixed_kinds() {
        let tree = StagingTree {
            entries: vec![
                StagingTreeEntry {
                    path: "README".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: sample_object_id('1'),
                },
                StagingTreeEntry {
                    path: "run.sh".to_string(),
                    kind: TreeEntryKind::Executable,
                    sha: sample_object_id('2'),
                },
                StagingTreeEntry {
                    path: "link".to_string(),
                    kind: TreeEntryKind::Symlink,
                    sha: sample_object_id('3'),
                },
                StagingTreeEntry {
                    path: "src".to_string(),
                    kind: TreeEntryKind::Subtree,
                    sha: sample_object_id('4'),
                },
                StagingTreeEntry {
                    path: "vendor".to_string(),
                    kind: TreeEntryKind::Submodule,
                    sha: sample_object_id('5'),
                },
            ],
        };
        let bytes = serialize_tree_object(&tree);
        let parsed = parse_tree_object(&bytes).expect("round-trip parse");
        assert_eq!(parsed, tree);
    }

    #[test]
    fn parse_tree_object_accepts_padded_subtree_mode() {
        let canonical = StagingTree {
            entries: vec![StagingTreeEntry {
                path: "src".to_string(),
                kind: TreeEntryKind::Subtree,
                sha: sample_object_id('a'),
            }],
        };
        let mut padded = Vec::new();
        padded.extend_from_slice(b"040000 src\0");
        padded.extend_from_slice(&hex_decode(canonical.entries[0].sha.as_str()));
        let parsed = parse_tree_object(&padded).expect("padded subtree mode accepted");
        assert_eq!(parsed, canonical);
    }

    #[test]
    fn parse_tree_object_rejects_unknown_mode() {
        // 100000 is not a recognized git mode.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100000 oddball\0");
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        let err = parse_tree_object(&bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::UnknownTreeMode(ref m) if m == "100000"),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_tree_object_rejects_truncated_sha() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 short\0");
        bytes.extend_from_slice(&[0u8; 19]); // one byte short
        let err = parse_tree_object(&bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::MalformedTreeEntry(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_identity_handles_negative_offset() {
        // Halifax, NS would emit `-0330`.
        let bytes = b"Halifax <hx@example.invalid> 1700000000 -0330";
        let identity = parse_identity(bytes).expect("negative tz parses");
        // Round-trip: serialize and parse should match.
        let serialized = serialize_identity(&identity);
        assert_eq!(serialized, "Halifax <hx@example.invalid> 1700000000 -0330");
    }

    #[test]
    fn parse_identity_handles_empty_name() {
        let bytes = b" <only-email@example.invalid> 1700000000 +0000";
        let identity = parse_identity(bytes).expect("empty-name identity parses");
        assert_eq!(identity.name(), "");
        assert_eq!(identity.email(), "only-email@example.invalid");
    }

    #[test]
    fn parse_tz_offset_rejects_multibyte_chars_without_panic() {
        // Regression for codex review P2: `+1é2` is 5 bytes but the
        // 2nd char `é` straddles bytes 1..3, so a `&str`-based slice
        // would panic on a non-char boundary. The parser must
        // surface this as a Malformed error instead.
        let err = parse_tz_offset("+1é2").expect_err("multibyte tz must fail cleanly");
        assert!(
            matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("ASCII digits")),
            "got: {err:?}"
        );

        // Sanity: a 5-byte string whose last byte is a UTF-8
        // continuation should also fail cleanly, not panic.
        let err = parse_tz_offset("+0é0").err();
        assert!(err.is_some(), "expected Err, got Ok");

        // And a fully-multibyte 5-byte string ("é" + "é" = 4 bytes,
        // pad to 5 with "X").
        let err = parse_tz_offset("ééX").err();
        assert!(err.is_some(), "expected Err, got Ok");
    }

    #[test]
    fn parse_identity_rejects_missing_angle_brackets() {
        let bytes = b"Alice email-without-brackets 1700000000 +0000";
        let err = parse_identity(bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::MalformedIdentity(_)),
            "got: {err:?}"
        );
    }

    // ============== Property tests ==============

    fn arb_object_id() -> impl Strategy<Value = GitObjectId> {
        prop::collection::vec(any::<u8>(), 20)
            .prop_map(|bytes| GitObjectId::new(hex_encode(&bytes)).unwrap())
    }

    fn arb_name() -> impl Strategy<Value = String> {
        // Names exclude `<`, `>`, and `\n` so they don't collide
        // with git's identity framing.
        prop::collection::vec(
            prop::char::any().prop_filter("no framing chars", |c| {
                *c != '<' && *c != '>' && *c != '\n' && *c != '\0'
            }),
            0..32,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>().trim().to_string())
    }

    fn arb_email() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::char::any().prop_filter("no framing chars", |c| {
                *c != '<' && *c != '>' && *c != '\n' && *c != ' ' && *c != '\0'
            }),
            1..32,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn arb_identity() -> impl Strategy<Value = CommitIdentity> {
        (
            arb_name(),
            arb_email(),
            // Bound the timestamp to a range comfortably inside
            // OffsetDateTime's representable window.
            -2_000_000_000_i64..2_000_000_000_i64,
            // Whole-minute offset between -14:00 and +14:00 (the
            // wider range OffsetDateTime accepts).
            -14_i32 * 60..=14_i32 * 60,
        )
            .prop_map(|(name, email, ts, offset_minutes)| {
                let offset = time::UtcOffset::from_whole_seconds(offset_minutes * 60).unwrap();
                let dt = OffsetDateTime::from_unix_timestamp(ts)
                    .unwrap()
                    .to_offset(offset);
                CommitIdentity::new(name, email, dt).unwrap()
            })
    }

    fn arb_message() -> impl Strategy<Value = String> {
        // Body bytes are unconstrained UTF-8.
        ".*".prop_map(|s: String| s)
    }

    fn arb_staging_commit() -> impl Strategy<Value = StagingCommit> {
        (
            arb_object_id(),
            prop_vec(arb_object_id(), 0..4),
            arb_identity(),
            arb_identity(),
            arb_message(),
        )
            .prop_map(
                |(tree, parents, author, committer, message)| StagingCommit {
                    tree,
                    parents,
                    author,
                    committer,
                    message,
                },
            )
    }

    fn arb_tree_entry_kind() -> impl Strategy<Value = TreeEntryKind> {
        prop_oneof![
            Just(TreeEntryKind::Blob),
            Just(TreeEntryKind::Executable),
            Just(TreeEntryKind::Symlink),
            Just(TreeEntryKind::Subtree),
            Just(TreeEntryKind::Submodule),
        ]
    }

    fn arb_tree_path() -> impl Strategy<Value = String> {
        // Path bytes exclude '\0' (entry terminator) and SP (mode/path
        // separator); git itself enforces neither but our parser
        // would mis-frame them.
        prop::collection::vec(
            prop::char::any().prop_filter("no framing chars", |c| *c != '\0' && *c != ' '),
            1..32,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn arb_staging_tree_entry() -> impl Strategy<Value = StagingTreeEntry> {
        (arb_tree_path(), arb_tree_entry_kind(), arb_object_id())
            .prop_map(|(path, kind, sha)| StagingTreeEntry { path, kind, sha })
    }

    fn arb_staging_tree() -> impl Strategy<Value = StagingTree> {
        prop_vec(arb_staging_tree_entry(), 0..16).prop_map(|entries| StagingTree { entries })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn commit_serialize_parse_round_trips(commit in arb_staging_commit()) {
            let bytes = serialize_commit_object(&commit);
            let parsed = parse_commit_object(&bytes).expect("round-trip parse");
            prop_assert_eq!(parsed, commit);
        }

        #[test]
        fn tree_serialize_parse_round_trips(tree in arb_staging_tree()) {
            let bytes = serialize_tree_object(&tree);
            let parsed = parse_tree_object(&bytes).expect("round-trip parse");
            prop_assert_eq!(parsed, tree);
        }
    }

    // ============== Integration test (real git) ==============

    /// Helper for sync git invocations from tests: avoids the
    /// hardened-env machinery and just runs git with default env
    /// rooted at the test tempdir.
    fn run_git(repo: &Path, args: &[&str]) -> String {
        let output = StdCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            output.status.success(),
            "git {args:?} failed: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8(output.stdout)
            .expect("git stdout utf8")
            .trim_end_matches('\n')
            .to_string()
    }

    fn run_git_stdin(repo: &Path, args: &[&str], stdin: &[u8]) -> String {
        use std::io::Write as _;
        let mut child = StdCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin)
            .expect("write stdin");
        let output = child.wait_with_output().expect("git wait");
        assert!(
            output.status.success(),
            "git {args:?} failed: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8(output.stdout)
            .expect("git stdout utf8")
            .trim_end_matches('\n')
            .to_string()
    }

    fn locate_git() -> std::path::PathBuf {
        // Tests run in the host environment with PATH set, so just
        // ask `which` via the std lib. resolve_program_for_clean_env
        // (the real production path) does the same walk.
        let path = std::env::var_os("PATH").expect("PATH set in tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("git");
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("git not found on PATH");
    }

    #[tokio::test]
    async fn cat_file_source_reads_blob_tree_and_commit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        run_git(repo, &["init", "--bare"]);

        // Seed a blob.
        let blob_content = b"hello world\n";
        let blob_sha = run_git_stdin(repo, &["hash-object", "-w", "--stdin"], blob_content);
        let blob_id = GitObjectId::new(blob_sha).expect("valid sha");

        // Seed a tree containing the blob.
        let tree_def = format!("100644 blob {}\tREADME\n", blob_id.as_str());
        let tree_sha = run_git_stdin(repo, &["mktree"], tree_def.as_bytes());
        let tree_id = GitObjectId::new(tree_sha).expect("valid sha");

        // Seed a commit with explicit author/committer dates so the
        // parser's date round-trip is deterministic.
        let commit_sha = {
            let mut cmd = StdCommand::new("git");
            cmd.arg("-C").arg(repo);
            cmd.arg("commit-tree").arg(tree_id.as_str());
            cmd.arg("-m").arg("seed commit");
            cmd.env("GIT_AUTHOR_NAME", "Author Person");
            cmd.env("GIT_AUTHOR_EMAIL", "author@example.invalid");
            cmd.env("GIT_AUTHOR_DATE", "1700000000 +0100");
            cmd.env("GIT_COMMITTER_NAME", "Committer Person");
            cmd.env("GIT_COMMITTER_EMAIL", "committer@example.invalid");
            cmd.env("GIT_COMMITTER_DATE", "1700000000 +0100");
            let out = cmd.output().expect("commit-tree");
            assert!(
                out.status.success(),
                "stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            GitObjectId::new(
                String::from_utf8(out.stdout)
                    .expect("utf8 sha")
                    .trim_end_matches('\n')
                    .to_string(),
            )
            .expect("valid sha")
        };

        let git = locate_git();
        let source = CatFileObjectSource::open(repo, &git)
            .await
            .expect("open cat-file");

        let blob = source.read_blob(&blob_id).await.expect("read_blob");
        assert_eq!(blob, blob_content);

        let tree = source.read_tree(&tree_id).await.expect("read_tree");
        assert_eq!(tree.entries.len(), 1);
        assert_eq!(tree.entries[0].path, "README");
        assert_eq!(tree.entries[0].kind, TreeEntryKind::Blob);
        assert_eq!(tree.entries[0].sha, blob_id);

        let commit = source.read_commit(&commit_sha).await.expect("read_commit");
        assert_eq!(commit.tree, tree_id);
        assert!(commit.parents.is_empty());
        assert_eq!(commit.author.name(), "Author Person");
        assert_eq!(commit.author.email(), "author@example.invalid");
        assert_eq!(commit.committer.name(), "Committer Person");
        assert_eq!(commit.message, "seed commit\n");

        source.close().await.expect("close cleanly");
    }

    #[tokio::test]
    async fn cat_file_source_reports_missing_objects() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        run_git(repo, &["init", "--bare"]);

        let git = locate_git();
        let source = CatFileObjectSource::open(repo, &git)
            .await
            .expect("open cat-file");

        let missing = sample_object_id('0');
        let err = source
            .read_blob(&missing)
            .await
            .expect_err("missing should error");
        assert!(
            matches!(err, GitObjectSourceError::NotFound { ref sha } if sha == missing.as_str()),
            "got: {err:?}"
        );

        source.close().await.expect("close cleanly");
    }

    #[tokio::test]
    async fn cat_file_source_reports_wrong_type() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        run_git(repo, &["init", "--bare"]);

        // Use a blob body whose length is large enough that, if the
        // implementation forgets to drain the response on a type
        // mismatch, the leftover bytes are guaranteed to corrupt the
        // next reply's header. A short body could coincidentally
        // happen to round-trip.
        let blob_body = b"x".repeat(64);
        let blob_sha = run_git_stdin(repo, &["hash-object", "-w", "--stdin"], &blob_body);
        let blob_id = GitObjectId::new(blob_sha).expect("valid sha");

        // Second blob with distinct contents so the post-mismatch
        // read has to return *its* bytes, not the first blob's.
        let other_body = b"second blob\n";
        let other_sha = run_git_stdin(repo, &["hash-object", "-w", "--stdin"], other_body);
        let other_id = GitObjectId::new(other_sha).expect("valid sha");

        let git = locate_git();
        let source = CatFileObjectSource::open(repo, &git)
            .await
            .expect("open cat-file");

        // Ask for a blob as if it were a tree.
        let err = source
            .read_tree(&blob_id)
            .await
            .expect_err("type mismatch should error");
        assert!(
            matches!(err, GitObjectSourceError::Malformed { ref reason, .. } if reason.contains("expected `tree`")),
            "got: {err:?}"
        );

        // Regression for codex review P2: a type mismatch must
        // drain the response payload so the next request is framed
        // against fresh bytes. Without the fix this read either
        // hangs, errors on a malformed header, or returns wrong
        // data.
        let recovered = source
            .read_blob(&other_id)
            .await
            .expect("read after mismatch");
        assert_eq!(recovered, other_body);

        source.close().await.expect("close cleanly");
    }

    #[tokio::test]
    async fn cat_file_source_close_reports_non_zero_exit() {
        // Point `git -C` at a path that does not exist. The cat-file
        // child exits with a non-zero status long before we call
        // close(), so wait() will see the failure and close() must
        // surface it instead of silently returning Ok.
        let tmp = tempfile::tempdir().expect("tempdir");
        let nonexistent = tmp.path().join("does-not-exist");
        assert!(!nonexistent.exists());

        let git = locate_git();
        let source = CatFileObjectSource::open(&nonexistent, &git)
            .await
            .expect("open succeeds (spawn does not wait)");

        let err = source
            .close()
            .await
            .expect_err("close must surface non-zero exit");
        let msg = err.to_string();
        assert!(
            msg.contains("non-zero status"),
            "expected non-zero-status diagnostic, got: {msg}"
        );
    }

    #[tokio::test]
    async fn cat_file_source_drop_kills_process_group() {
        // Regression for codex review P2: dropping the source must
        // SIGKILL the *whole* process group, not just the leader pid.
        // A wrapper script forks a long-lived sibling into the
        // shared pgid, records its pid, then sleeps so the leader
        // stays alive until Drop runs. If Drop only killed the
        // leader (the buggy behaviour), the sibling would survive.
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let wrapper = tmp.path().join("wrap.sh");
        let helper_pid_file = tmp.path().join("helper.pid");
        let script = format!(
            "#!/bin/sh\n\
             sleep 600 &\n\
             echo $! > {helper}\n\
             exec sleep 600\n",
            helper = helper_pid_file.display(),
        );
        std::fs::write(&wrapper, script).expect("write wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
            .expect("chmod wrapper");

        let helper_pid = {
            let _source = CatFileObjectSource::open(tmp.path(), &wrapper)
                .await
                .expect("open wrapper");
            // Wait for the wrapper to fork the helper and write its
            // pid. Generous deadline to keep CI happy.
            let mut helper_pid: Option<libc::pid_t> = None;
            for _ in 0..200 {
                if let Ok(raw) = std::fs::read_to_string(&helper_pid_file) {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        helper_pid = Some(trimmed.parse().expect("helper pid is integer"));
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            let pid = helper_pid.expect("wrapper recorded helper pid before timeout");
            // Confirm the helper is alive while the source still
            // exists; otherwise the test is meaningless.
            let alive = unsafe { libc::kill(pid, 0) };
            assert_eq!(
                alive,
                0,
                "helper {pid} should be alive before source drop (errno={})",
                std::io::Error::last_os_error()
            );
            pid
            // `source` goes out of scope here → Drop runs → killpg
        };

        // After Drop, the helper must die. SIGKILL is synchronous
        // at the kernel level, but the process state visible via
        // kill(0) can take a tick. Poll briefly.
        let mut gone = false;
        for _ in 0..200 {
            let r = unsafe { libc::kill(helper_pid, 0) };
            if r == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::ESRCH) {
                    gone = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            gone,
            "helper pid {helper_pid} survived source Drop — process group was not killed"
        );
    }

    #[tokio::test]
    async fn cat_file_source_close_cancellation_kills_process_group() {
        // Regression for codex review P2: cancelling `close()` at
        // its `child.wait().await` must still SIGKILL the whole
        // process group. The wrapper `exec sleep`s, so it never
        // observes the EOF that `close()` writes to its stdin —
        // the only way to cancel cleanup is to drop the future.
        // Without the local PgidCleanupGuard inside `close()` the
        // outer Drop sees `inner == None` and skips `killpg`,
        // leaking the helper.
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let wrapper = tmp.path().join("wrap.sh");
        let helper_pid_file = tmp.path().join("helper.pid");
        let script = format!(
            "#!/bin/sh\n\
             sleep 600 &\n\
             echo $! > {helper}\n\
             exec sleep 600\n",
            helper = helper_pid_file.display(),
        );
        std::fs::write(&wrapper, script).expect("write wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
            .expect("chmod wrapper");

        let source = CatFileObjectSource::open(tmp.path(), &wrapper)
            .await
            .expect("open wrapper");

        let mut helper_pid: Option<libc::pid_t> = None;
        for _ in 0..200 {
            if let Ok(raw) = std::fs::read_to_string(&helper_pid_file) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    helper_pid = Some(trimmed.parse().expect("integer pid"));
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let helper_pid = helper_pid.expect("helper pid recorded before timeout");

        // `close()` hangs at `child.wait()` because the wrapper
        // ignores stdin EOF. tokio::time::timeout drops the inner
        // future on elapsed, which is the cancellation path under
        // test.
        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), source.close()).await;
        assert!(
            timeout_result.is_err(),
            "close should have been cancelled by timeout, got {timeout_result:?}",
        );

        // The local cleanup guard inside close() must have killpg'd
        // when the future was dropped, so the helper should be gone.
        let mut gone = false;
        for _ in 0..200 {
            let r = unsafe { libc::kill(helper_pid, 0) };
            if r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            gone,
            "helper pid {helper_pid} survived close() cancellation — group cleanup did not run"
        );
    }
}
