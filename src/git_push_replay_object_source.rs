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
//! [`crate::git_push_replay_object_parse`] — pure functions over
//! `&[u8]` so property tests can drive them without any I/O. This
//! module is purely the imperative shell that hands them the bytes a
//! `git cat-file --batch` reply produced.
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

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::clean_git::{self, CLEAN_GIT_CONFIG_ENV, CLEAN_GIT_CURRENT_DIR, CleanGitError};
use crate::git_push_replay_object_parse::{parse_commit_object, parse_tree_object};
use crate::git_push_replay_walker::{
    GitObjectSource, GitObjectSourceError, StagingCommit, StagingTree,
};
use crate::process_spawn;
use crate::vm_git::GitObjectId;

pub struct CatFileObjectSource {
    /// Process group id of the cat-file leader. The child is spawned
    /// with `process_group(0)`, so this equals the leader's pid and is
    /// inherited by any helper the leader forks (or by anything inside
    /// the configured `git_program` if it is a wrapper script). Stored
    /// at the top level so [`Drop`] can `killpg` the whole group
    /// without needing access to the child through the mutex.
    pgid: libc::pid_t,
    /// Hard cap on the declared (uncompressed) size of any single
    /// `cat-file` response payload. The staging repo is built from
    /// an untrusted bundle, so the size field in a cat-file header
    /// is attacker-controlled; without this cap a small compressed
    /// pack could declare a multi-gigabyte object and OOM the
    /// broker on the pre-allocation in `read_object_raw`. The first
    /// header that exceeds this cap poisons the source: subsequent
    /// reads return [`GitObjectSourceError::Poisoned`] and the
    /// cat-file process group is killed, because the wire framing
    /// is no longer recoverable (the declared payload bytes never
    /// came out of stdout).
    max_object_bytes: u64,
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
    /// Set when an over-limit response (or any other unrecoverable
    /// framing error) leaves the wire out of sync. Once true,
    /// `read_object_raw` returns `Poisoned` without touching stdin
    /// or stdout.
    poisoned: bool,
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
    pub async fn open(
        staging_repo: &Path,
        git_program: &Path,
        max_object_bytes: u64,
    ) -> Result<Self, OpenError> {
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
            max_object_bytes,
            inner: Some(Mutex::new(CatFileChild {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                poisoned: false,
            })),
        })
    }

    /// Close the child gracefully: drop stdin to signal EOF, wait
    /// for the leader to exit without reaping, SIGKILL anything
    /// else in the process group, then reap the leader. Returns
    /// the exit status as an error if the child exited non-zero.
    ///
    /// The waitid-then-killpg-then-wait ordering keeps the leader's
    /// pid claimed by the leader (un-reaped) while we send
    /// `killpg`, which is the only way to avoid a pid-recycle race
    /// where the kernel could reuse the leader's pid for an
    /// unrelated process group between `wait()` and `killpg`. The
    /// same pattern is in `clean_git::execute_clean_git`.
    ///
    /// Cancellation safety: from the moment we take ownership of
    /// the child the source's outer [`Drop`] is disarmed (`inner`
    /// is `None`), so a local [`PgidCleanupGuard`] takes over and
    /// SIGKILLs the process group if anything between here and the
    /// final `disarm()` panics or has its await cancelled.
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
            poisoned: _,
        } = mutex.into_inner();
        drop(stdin);
        drop(stdout);

        // Observe the leader's exit without reaping. While its pid
        // remains claimed, the pgid is stable, so the subsequent
        // killpg cannot hit an unrelated recycled group.
        let observed_exit = wait_for_pid_exit_no_reap(pgid).await?;
        // Send SIGKILL to the whole group: helpers (if any) die,
        // and the leader (already exited) is a no-op.
        kill_process_group_best_effort(pgid, observed_exit)?;
        // Now it is safe to reap the leader and free its pid.
        let status = child.wait().await?;
        guard.disarm();
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

fn kill_process_group_best_effort(pgid: libc::pid_t, leader_exit_observed: bool) -> io::Result<()> {
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // No such process group: somebody already cleaned up.
        Some(libc::ESRCH) => Ok(()),
        // macOS can report EPERM once the leader has exited and no
        // signalable members remain. We only accept EPERM if we
        // have just observed the leader exit via waitid(WNOWAIT) —
        // otherwise EPERM means something else and we should not
        // silently swallow it.
        Some(libc::EPERM) if leader_exit_observed => Ok(()),
        _ => Err(err),
    }
}

const PID_EXIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// Poll `waitid(WNOWAIT)` until the given pid is observed in the
/// exited state without being reaped. Returns once exit is
/// observed. The caller must keep the [`tokio::process::Child`]
/// alive (un-`wait`-ed) until this returns so the pid still
/// belongs to the leader.
async fn wait_for_pid_exit_no_reap(pid: libc::pid_t) -> io::Result<bool> {
    loop {
        if pid_has_exited_without_reaping(pid)? {
            return Ok(true);
        }
        tokio::time::sleep(PID_EXIT_POLL_INTERVAL).await;
    }
}

fn pid_has_exited_without_reaping(pid: libc::pid_t) -> io::Result<bool> {
    use std::mem::MaybeUninit;
    let mut status = MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            status.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    let status = unsafe { status.assume_init() };
    let observed_pid = unsafe { status.si_pid() };
    Ok(observed_pid != 0)
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
        let raw = self.read_object_raw(sha, "commit").await?;
        parse_commit_object(&raw).map_err(|reason| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: reason.to_string(),
        })
    }

    async fn read_tree(&self, sha: &GitObjectId) -> Result<StagingTree, GitObjectSourceError> {
        let raw = self.read_object_raw(sha, "tree").await?;
        parse_tree_object(&raw).map_err(|reason| GitObjectSourceError::Malformed {
            sha: sha.as_str().to_string(),
            reason: reason.to_string(),
        })
    }

    async fn read_blob(&self, sha: &GitObjectId) -> Result<Vec<u8>, GitObjectSourceError> {
        self.read_object_raw(sha, "blob").await
    }
}

impl CatFileObjectSource {
    async fn read_object_raw(
        &self,
        sha: &GitObjectId,
        expected_type: &str,
    ) -> Result<Vec<u8>, GitObjectSourceError> {
        let mut guard = self.child_mutex().lock().await;
        let child = &mut *guard;
        if child.poisoned {
            return Err(GitObjectSourceError::Poisoned);
        }

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
        // `missing` and `ambiguous` carry no payload, so we can
        // return immediately without disturbing the pipe framing.
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
        // Parse the declared size as u64 before comparing to the
        // configured cap, so an attacker-controlled bundle cannot
        // overflow usize on a 32-bit target into a small allocation.
        let declared_size: u64 =
            size_field
                .parse()
                .map_err(|err: ParseIntError| GitObjectSourceError::Malformed {
                    sha: sha.as_str().to_string(),
                    reason: format!("cat-file size field {size_field:?} is not a u64: {err}"),
                })?;
        if declared_size > self.max_object_bytes {
            // The wire framing is now permanently out of sync: we
            // signalled to cat-file that we would read `declared_size`
            // payload bytes, and we are about to refuse them. The
            // next request's response would land partway through this
            // object's body. Mark the source poisoned, kill the
            // process group so the leader stops emitting bytes we
            // would never drain, and return.
            child.poisoned = true;
            kill_process_group_best_effort(self.pgid, false)
                .map_err(|source| GitObjectSourceError::Io { source })?;
            return Err(GitObjectSourceError::ObjectTooLarge {
                sha: sha.as_str().to_string(),
                size: declared_size,
                max: self.max_object_bytes,
            });
        }
        // Safe: declared_size <= max_object_bytes <= u64, and the
        // production cap will be set well below usize::MAX. On a
        // 32-bit host the cap must be < 4 GiB; we rely on the
        // operator setting it appropriately.
        let size: usize =
            declared_size
                .try_into()
                .map_err(|_| GitObjectSourceError::Malformed {
                    sha: sha.as_str().to_string(),
                    reason: format!(
                        "cat-file size {declared_size} fits within the cap but not in usize on this host"
                    ),
                })?;

        // Drain the full payload (size bytes + trailing LF) before
        // applying the type check. Returning early on a type
        // mismatch without consuming the body would leave the next
        // caller's read_* framed against the tail of this object's
        // bytes, silently corrupting every subsequent read.
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
}

#[cfg(test)]
mod tests {
    use std::process::Command as StdCommand;

    use super::*;
    use crate::github_git_db::TreeEntryKind;

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
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
        let source = CatFileObjectSource::open(repo, &git, 256 << 20)
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
        let source = CatFileObjectSource::open(repo, &git, 256 << 20)
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
        let source = CatFileObjectSource::open(repo, &git, 256 << 20)
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
        let source = CatFileObjectSource::open(&nonexistent, &git, 256 << 20)
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
    async fn cat_file_source_rejects_oversized_payload_and_poisons_source() {
        // Regression for codex round-1 P1: when the staging repo is
        // an untrusted bundle, the size field in a cat-file header
        // is attacker-controlled. Allocating `Vec::with_capacity`
        // for that size lets a small, valid-looking bundle declare
        // a multi-gigabyte object and OOM the broker. The
        // `read_object_raw` path must compare the declared size to
        // the configured cap *before* allocating, abort the source
        // on over-limit, and refuse all subsequent reads (the wire
        // framing is now hosed because we never consumed the
        // declared payload bytes).
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let wrapper = tmp.path().join("wrap.sh");
        // The wrapper reads one SHA, claims it is a 10 GiB blob,
        // and then sleeps so the test still controls process
        // lifetime. We never actually emit the payload bytes.
        let script = "#!/bin/sh\n\
                      read -r sha\n\
                      printf '%s blob 10737418240\\n' \"$sha\"\n\
                      exec sleep 600\n";
        std::fs::write(&wrapper, script).expect("write wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
            .expect("chmod wrapper");

        // 1 MiB cap — well below the declared 10 GiB.
        let source = CatFileObjectSource::open(tmp.path(), &wrapper, 1 << 20)
            .await
            .expect("open wrapper");

        let target = sample_object_id('a');
        let err = source
            .read_blob(&target)
            .await
            .expect_err("oversized declared size must be rejected pre-allocation");
        match err {
            GitObjectSourceError::ObjectTooLarge { ref sha, size, max } => {
                assert_eq!(sha, target.as_str());
                assert_eq!(size, 10_737_418_240);
                assert_eq!(max, 1 << 20);
            }
            other => panic!("expected ObjectTooLarge, got: {other:?}"),
        }

        // Subsequent reads must fail fast — the source has been
        // poisoned and the wire framing is no longer recoverable.
        let err = source
            .read_blob(&target)
            .await
            .expect_err("source must be poisoned after over-limit");
        assert!(
            matches!(err, GitObjectSourceError::Poisoned),
            "got: {err:?}"
        );

        // We deliberately do not `close()` here: aborting on
        // over-limit kills the process group, so any close() call
        // would race against the SIGKILL'd child. Dropping the
        // source is the documented post-poison cleanup path.
        drop(source);
    }

    /// True iff `pid` has had a fatal signal delivered: either the
    /// process is fully gone from the process table, or it is a
    /// zombie awaiting reap.
    ///
    /// We can't use `kill(pid, 0) == ESRCH` here: a zombie still has
    /// a pid-table entry, so `kill(pid, 0)` returns 0 for zombies
    /// and only flips to ESRCH after the zombie is reaped. In these
    /// tests the helper is re-parented to init/launchd after the
    /// wrapper dies, and under heavy parallel test load init/launchd
    /// can take many seconds to reap — long enough to blow past any
    /// reasonable polling deadline. What we actually want to assert
    /// is that the helper received SIGKILL; both "gone" and "zombie"
    /// satisfy that, so we ask `ps` for the process state directly.
    fn helper_has_been_killed(pid: libc::pid_t) -> bool {
        let output = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "stat="])
            .output();
        match output {
            Ok(o) => {
                let stat = String::from_utf8_lossy(&o.stdout);
                let stat = stat.trim();
                stat.is_empty() || stat.starts_with('Z')
            }
            Err(_) => false,
        }
    }

    async fn wait_until_helper_killed(pid: libc::pid_t) -> bool {
        // 30s wall-clock budget: comfortably longer than any plausible
        // signal-delivery delay even under crushing parallel test
        // load, but short enough that a genuine bug (kill never
        // delivered) fails the test promptly.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if helper_has_been_killed(pid) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// Poll `helper_pid_file` until the wrapper script has written
    /// its background-child's pid. Under crushing parallel test load
    /// on macOS the wrapper's fork/exec can stall for several seconds
    /// before it gets scheduled, so we use a 30s wall-clock deadline.
    async fn wait_for_helper_pid(helper_pid_file: &std::path::Path) -> Option<libc::pid_t> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if let Ok(raw) = std::fs::read_to_string(helper_pid_file) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.parse().expect("helper pid is integer"));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        None
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
            let _source = CatFileObjectSource::open(tmp.path(), &wrapper, 256 << 20)
                .await
                .expect("open wrapper");
            let pid = wait_for_helper_pid(&helper_pid_file)
                .await
                .expect("wrapper recorded helper pid before timeout");
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

        // After Drop, the helper must die. SIGKILL is synchronous at
        // the kernel level; the helper transitions to zombie state
        // immediately, and `helper_has_been_killed` accepts that.
        assert!(
            wait_until_helper_killed(helper_pid).await,
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

        let source = CatFileObjectSource::open(tmp.path(), &wrapper, 256 << 20)
            .await
            .expect("open wrapper");

        let helper_pid = wait_for_helper_pid(&helper_pid_file)
            .await
            .expect("helper pid recorded before timeout");

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
        // when the future was dropped, so the helper should now be
        // dead (zombie or fully gone — see `helper_has_been_killed`).
        assert!(
            wait_until_helper_killed(helper_pid).await,
            "helper pid {helper_pid} survived close() cancellation — group cleanup did not run"
        );
    }
}
