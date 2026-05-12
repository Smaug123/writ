//! Staged-push replay: planning and staging-repo preparation.
//!
//! Replay re-creates every commit between an upstream branch tip and a
//! VM-supplied bundle tip via the GitHub `blobs`/`trees`/`commits` REST
//! surface under the host App's identity, so the published commits carry
//! the Verified badge while preserving provenance back to the bundle.
//!
//! This module owns the inert plan description ([`GitPushReplayPlan`],
//! [`TrailerSource`]) plus the first executor slice: [`prepare_staging_repo`]
//! creates a fresh bare repository with mode `0o700` ownership, ready to
//! receive the bundle objects. Bundle ingestion itself (which must first
//! seed any prerequisite commit referenced via `--not <expected>` from
//! origin) lives in a follow-up commit, as do the per-commit GitHub
//! upload, the merge-base walk, and the ref update.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use crate::clean_git::{self, CleanGitError, CleanGitInvocation, clean_git_config_env};
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

const REPLAY_BARE_REPO_MODE: u32 = 0o700;

/// A complete description of one replay operation: where the bundle lives
/// on disk, the bare repository the bundle will be ingested into, the
/// GitHub destination, and the trailers to append to each replayed
/// commit's message so reviewers can map App-owned commits back to the
/// bundle commits they were derived from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushReplayPlan {
    git_program: PathBuf,
    bundle_path: PathBuf,
    staging_repo: PathBuf,
    repo: GitCloneRepo,
    branch: GitBranchName,
    expected_remote_head: Option<GitObjectId>,
    new_head: GitObjectId,
    trailers: Vec<TrailerSource>,
    step_timeout: Duration,
}

/// One trailer to append to every replayed commit. Two shapes:
///
/// * [`TrailerSource::Fixed`] — the same `Key: value` on every commit. Use
///   for invariants like the broker session id or the operator who
///   promoted the staged push.
/// * [`TrailerSource::OriginalCommitSha`] — `Key: <bundle commit sha>` on
///   each replayed commit, so reviewers can trace any App-owned commit
///   back to the exact bundle commit it derived from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrailerSource {
    Fixed {
        key: TrailerKey,
        value: TrailerValue,
    },
    OriginalCommitSha {
        key: TrailerKey,
    },
}

/// The left side of a Git trailer (`Key: value`).
///
/// Git's own parser is permissive — anything before the first ` :` is a
/// candidate key — but the cost of accepting odd keys here is that the
/// rendered trailer block may not round-trip through other tools. The
/// validated shape matches conventional trailer keys (`Co-authored-by`,
/// `Signed-off-by`): non-empty, ASCII, starting with a letter, followed
/// by letters, digits, or `-`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrailerKey(String);

/// The right side of a Git trailer. Constrained at construction to forbid
/// the control bytes that would break the trailer block on output
/// (`\n`, `\r`, `\0`). Leading and trailing whitespace are preserved so
/// the plan is a faithful description of what the executor will emit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrailerValue(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GitPushReplayCommandStep {
    InitBareRepo,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitPushReplayPlanError {
    #[error("git_program path must not be empty")]
    EmptyGitProgram,
    #[error("{field} path must not be empty")]
    EmptyPath { field: &'static str },
    #[error("{field} path must be absolute: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("bundle path and staging repository path must differ: {0}")]
    BundleEqualsStagingRepo(PathBuf),
    #[error("step timeout must be nonzero")]
    ZeroStepTimeout,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TrailerKeyError {
    #[error("trailer key must not be empty")]
    Empty,
    #[error("trailer key must start with an ASCII letter: {0:?}")]
    InvalidStart(String),
    #[error(
        "trailer key must contain only ASCII letters, digits, or '-' after the first byte: {0:?}"
    )]
    InvalidByte(String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TrailerValueError {
    #[error("trailer value must not be empty")]
    Empty,
    #[error("trailer value must not contain '\\n', '\\r', or '\\0'")]
    ContainsControlByte,
}

#[derive(Debug, thiserror::Error)]
pub enum GitPushReplayRunError {
    #[error("staging repository path already exists before ingest: {0}")]
    StagingRepoAlreadyExists(PathBuf),
    #[error("cannot create staging repository directory {path}: {source}")]
    CreateStagingRepo {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot set staging repository permissions for {path}: {source}")]
    SetStagingRepoPermissions {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "git program must be absolute or discoverable on PATH before clearing the child environment: {0}"
    )]
    GitProgramNotFound(PathBuf),
    #[error("cannot canonicalize {field} path {path}: {source}")]
    Canonicalize {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{step} command could not be spawned: {source}")]
    Spawn {
        step: GitPushReplayCommandStep,
        source: std::io::Error,
    },
    #[error("{step} command wait failed: {source}")]
    Wait {
        step: GitPushReplayCommandStep,
        source: std::io::Error,
    },
    #[error("{step} command timed out after {timeout:?}")]
    TimedOut {
        step: GitPushReplayCommandStep,
        timeout: Duration,
    },
    #[error("{step} command failed with status {status}")]
    Failed {
        step: GitPushReplayCommandStep,
        status: ExitStatus,
    },
    #[error("{step} command did not expose a child process id")]
    MissingProcessId { step: GitPushReplayCommandStep },
    #[error("{step} child process id {pid} cannot be represented as a process group id")]
    InvalidProcessId {
        step: GitPushReplayCommandStep,
        pid: u32,
    },
    #[error("{step} process group {pgid} could not be killed after Git child exit: {source}")]
    KillProcessGroup {
        step: GitPushReplayCommandStep,
        pgid: libc::pid_t,
        source: std::io::Error,
    },
}

impl GitPushReplayPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        git_program: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        staging_repo: impl Into<PathBuf>,
        repo: GitCloneRepo,
        branch: GitBranchName,
        expected_remote_head: Option<GitObjectId>,
        new_head: GitObjectId,
        trailers: Vec<TrailerSource>,
        step_timeout: Duration,
    ) -> Result<Self, GitPushReplayPlanError> {
        let git_program = git_program.into();
        let bundle_path = bundle_path.into();
        let staging_repo = staging_repo.into();
        if git_program.as_os_str().is_empty() {
            return Err(GitPushReplayPlanError::EmptyGitProgram);
        }
        require_absolute_path("bundle_path", &bundle_path)?;
        require_absolute_path("staging_repo", &staging_repo)?;
        if bundle_path == staging_repo {
            return Err(GitPushReplayPlanError::BundleEqualsStagingRepo(bundle_path));
        }
        if step_timeout.is_zero() {
            return Err(GitPushReplayPlanError::ZeroStepTimeout);
        }
        Ok(Self {
            git_program,
            bundle_path,
            staging_repo,
            repo,
            branch,
            expected_remote_head,
            new_head,
            trailers,
            step_timeout,
        })
    }

    pub fn git_program(&self) -> &Path {
        &self.git_program
    }

    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    pub fn staging_repo(&self) -> &Path {
        &self.staging_repo
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn branch(&self) -> &GitBranchName {
        &self.branch
    }

    /// `None` means the replay is *creating* the branch on GitHub rather
    /// than fast-forwarding it. Walks from the merge-base with the
    /// repository's default branch instead of from a known parent tip.
    pub fn expected_remote_head(&self) -> Option<&GitObjectId> {
        self.expected_remote_head.as_ref()
    }

    pub fn new_head(&self) -> &GitObjectId {
        &self.new_head
    }

    pub fn trailers(&self) -> &[TrailerSource] {
        &self.trailers
    }

    pub fn step_timeout(&self) -> Duration {
        self.step_timeout
    }

    /// The `git init --bare` invocation that materialises the staging
    /// repository. Pure function of the plan — exposed so tests can pin
    /// the argv shape without running git.
    pub(crate) fn init_bare_command(&self) -> CleanGitInvocation {
        CleanGitInvocation::new(
            self.git_program.clone(),
            [
                OsString::from("init"),
                OsString::from("--bare"),
                OsString::from("--quiet"),
                OsString::from("--"),
                self.staging_repo.as_os_str().to_os_string(),
            ],
            clean_git_config_env(),
            Vec::new(),
        )
    }
}

impl TrailerSource {
    /// The trailer key, common to both variants.
    pub fn key(&self) -> &TrailerKey {
        match self {
            TrailerSource::Fixed { key, .. } | TrailerSource::OriginalCommitSha { key } => key,
        }
    }
}

impl TrailerKey {
    pub fn new(raw: impl Into<String>) -> Result<Self, TrailerKeyError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(TrailerKeyError::Empty);
        }
        let mut bytes = raw.bytes();
        // Cannot panic: emptiness ruled out above.
        let first = bytes.next().expect("non-empty");
        if !first.is_ascii_alphabetic() {
            return Err(TrailerKeyError::InvalidStart(raw));
        }
        for byte in bytes {
            if !is_trailer_key_byte(byte) {
                return Err(TrailerKeyError::InvalidByte(raw));
            }
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TrailerValue {
    pub fn new(raw: impl Into<String>) -> Result<Self, TrailerValueError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(TrailerValueError::Empty);
        }
        if raw.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
            return Err(TrailerValueError::ContainsControlByte);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrailerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for TrailerValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for GitPushReplayCommandStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitPushReplayCommandStep::InitBareRepo => f.write_str("init bare repo"),
        }
    }
}

/// Create the bare staging repository the rest of replay will operate on.
///
/// Two steps:
///
/// 1. Create the directory atomically with mode `0o700` (see
///    [`create_private_staging_repo`]) so a stale or attacker-planted
///    directory at the same path is rejected before any git command sees
///    it, and so the directory's contents are never world- or
///    group-readable.
/// 2. Run `git init --bare --quiet -- <staging>` against the hardened
///    `clean_git` invocation, which materialises the empty object
///    database and refs/ layout under the App's identity.
///
/// On success the returned [`PathBuf`] points at the fresh empty bare
/// repository. Pulling the bundle's objects into it (and seeding the
/// prerequisite commit referenced by `--not <expected>` from origin)
/// lives in a follow-up commit.
pub async fn prepare_staging_repo(
    plan: &GitPushReplayPlan,
) -> Result<PathBuf, GitPushReplayRunError> {
    create_private_staging_repo(plan).await?;
    run_replay_invocation(
        GitPushReplayCommandStep::InitBareRepo,
        &plan.init_bare_command(),
        plan.step_timeout(),
    )
    .await?;
    Ok(plan.staging_repo().to_path_buf())
}

/// Create the staging repo with mode `0o700`.
///
/// Two-step on purpose:
///
/// 1. `DirBuilder::mode(0o700).create(path)` (non-recursive) — passes the
///    mode straight to `mkdir(2)`, so the kernel applies it atomically.
///    Umask can only further restrict the bits, never widen them, so
///    the directory is never momentarily group- or other-readable. The
///    non-recursive `create` makes `AlreadyExists` the authoritative
///    "this path was not fresh" signal, with no TOCTOU window between a
///    stat preflight and the create.
/// 2. `set_permissions(0o700)` on the directory we just created. Step 1
///    can produce *narrower* permissions than `0o700` if the broker's
///    umask masks owner bits (e.g. an unusual `umask 0777`), which would
///    stop the next `git init --bare` from writing into the directory.
///    Step 2 makes the postcondition exact. Because the directory is
///    brand new and the path is only known to this process, broadening
///    permissions from "narrower than 0o700" back up to "exactly 0o700"
///    has no security window: nothing else can be holding the path open.
async fn create_private_staging_repo(
    plan: &GitPushReplayPlan,
) -> Result<(), GitPushReplayRunError> {
    let path = plan.staging_repo().to_path_buf();
    let result = tokio::task::spawn_blocking({
        let path = path.clone();
        move || {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .recursive(false)
                .mode(REPLAY_BARE_REPO_MODE)
                .create(&path)?;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(REPLAY_BARE_REPO_MODE),
            )
            .map_err(CreateOrChmodError::Chmod)
        }
    })
    .await
    .map_err(|join_err| GitPushReplayRunError::CreateStagingRepo {
        path: path.clone(),
        source: std::io::Error::other(join_err),
    })?;
    match result {
        Ok(()) => Ok(()),
        Err(CreateOrChmodError::Create(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(GitPushReplayRunError::StagingRepoAlreadyExists(path))
        }
        Err(CreateOrChmodError::Create(source)) => {
            Err(GitPushReplayRunError::CreateStagingRepo { path, source })
        }
        Err(CreateOrChmodError::Chmod(source)) => {
            Err(GitPushReplayRunError::SetStagingRepoPermissions { path, source })
        }
    }
}

/// Internal two-state result of [`create_private_staging_repo`]'s
/// blocking body so the caller can distinguish "the `mkdir` failed"
/// from "the follow-up `chmod` failed" when mapping to the public
/// `GitPushReplayRunError` variants.
enum CreateOrChmodError {
    Create(std::io::Error),
    Chmod(std::io::Error),
}

impl From<std::io::Error> for CreateOrChmodError {
    fn from(err: std::io::Error) -> Self {
        CreateOrChmodError::Create(err)
    }
}

async fn run_replay_invocation(
    step: GitPushReplayCommandStep,
    invocation: &CleanGitInvocation,
    timeout: Duration,
) -> Result<(), GitPushReplayRunError> {
    clean_git::run_clean_git(invocation, timeout, None)
        .await
        .map_err(|err| translate_clean_git_error(step, err))
}

fn translate_clean_git_error(
    step: GitPushReplayCommandStep,
    err: CleanGitError,
) -> GitPushReplayRunError {
    match err {
        CleanGitError::GitProgramNotFound(p) => GitPushReplayRunError::GitProgramNotFound(p),
        CleanGitError::Canonicalize {
            field,
            path,
            source,
        } => GitPushReplayRunError::Canonicalize {
            field,
            path,
            source,
        },
        CleanGitError::Spawn(source) => GitPushReplayRunError::Spawn { step, source },
        CleanGitError::Wait(source) => GitPushReplayRunError::Wait { step, source },
        CleanGitError::TimedOut(timeout) => GitPushReplayRunError::TimedOut { step, timeout },
        CleanGitError::Failed(status) => GitPushReplayRunError::Failed { step, status },
        CleanGitError::MissingProcessId => GitPushReplayRunError::MissingProcessId { step },
        CleanGitError::InvalidProcessId(pid) => {
            GitPushReplayRunError::InvalidProcessId { step, pid }
        }
        CleanGitError::KillProcessGroup { pgid, source } => {
            GitPushReplayRunError::KillProcessGroup { step, pgid, source }
        }
    }
}

fn is_trailer_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn require_absolute_path(field: &'static str, path: &Path) -> Result<(), GitPushReplayPlanError> {
    if path.as_os_str().is_empty() {
        return Err(GitPushReplayPlanError::EmptyPath { field });
    }
    if !path.is_absolute() {
        return Err(GitPushReplayPlanError::RelativePath {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::str::FromStr;

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    const TEST_STEP_TIMEOUT: Duration = Duration::from_secs(30);

    fn sample_repo() -> GitCloneRepo {
        GitCloneRepo::new("owner/name".parse().unwrap()).unwrap()
    }

    fn sample_branch() -> GitBranchName {
        GitBranchName::from_str("feature/x").unwrap()
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn sample_trailer() -> TrailerSource {
        TrailerSource::Fixed {
            key: TrailerKey::new("Co-authored-by").unwrap(),
            value: TrailerValue::new("Octocat <octocat@example.com>").unwrap(),
        }
    }

    fn sample_plan(
        git_program: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        staging_repo: impl Into<PathBuf>,
        new_head: GitObjectId,
    ) -> GitPushReplayPlan {
        GitPushReplayPlan::new(
            git_program,
            bundle_path,
            staging_repo,
            sample_repo(),
            sample_branch(),
            None,
            new_head,
            Vec::new(),
            TEST_STEP_TIMEOUT,
        )
        .unwrap()
    }

    #[test]
    fn plan_accepts_absolute_paths_and_distinct_locations() {
        let plan = GitPushReplayPlan::new(
            "/usr/bin/git",
            "/var/lib/writ/bundles/bundle.git",
            "/var/lib/writ/replay/staging.git",
            sample_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
            vec![sample_trailer()],
            TEST_STEP_TIMEOUT,
        )
        .unwrap();
        assert_eq!(plan.git_program(), Path::new("/usr/bin/git"));
        assert_eq!(
            plan.bundle_path(),
            Path::new("/var/lib/writ/bundles/bundle.git")
        );
        assert_eq!(
            plan.staging_repo(),
            Path::new("/var/lib/writ/replay/staging.git")
        );
        assert_eq!(plan.repo(), &sample_repo());
        assert_eq!(plan.branch(), &sample_branch());
        assert_eq!(plan.expected_remote_head(), Some(&sample_object_id('a')));
        assert_eq!(plan.new_head(), &sample_object_id('b'));
        assert_eq!(plan.trailers().len(), 1);
        assert_eq!(plan.step_timeout(), TEST_STEP_TIMEOUT);
    }

    #[test]
    fn plan_rejects_empty_git_program() {
        let err = GitPushReplayPlan::new(
            "",
            "/abs/bundle.pack",
            "/abs/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('e'),
            Vec::new(),
            TEST_STEP_TIMEOUT,
        )
        .unwrap_err();
        assert!(matches!(err, GitPushReplayPlanError::EmptyGitProgram));
    }

    #[test]
    fn plan_rejects_empty_bundle_path() {
        let err = GitPushReplayPlan::new(
            "/usr/bin/git",
            "",
            "/var/lib/writ/replay/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('b'),
            Vec::new(),
            TEST_STEP_TIMEOUT,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitPushReplayPlanError::EmptyPath {
                field: "bundle_path"
            }
        ));
    }

    #[test]
    fn plan_rejects_relative_staging_repo() {
        let err = GitPushReplayPlan::new(
            "/usr/bin/git",
            "/abs/bundle.pack",
            "relative/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('c'),
            Vec::new(),
            TEST_STEP_TIMEOUT,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitPushReplayPlanError::RelativePath {
                field: "staging_repo",
                ..
            }
        ));
    }

    #[test]
    fn plan_rejects_bundle_equal_to_staging_repo() {
        let err = GitPushReplayPlan::new(
            "/usr/bin/git",
            "/var/lib/writ/replay/same",
            "/var/lib/writ/replay/same",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('d'),
            Vec::new(),
            TEST_STEP_TIMEOUT,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitPushReplayPlanError::BundleEqualsStagingRepo(_)
        ));
    }

    #[test]
    fn plan_rejects_zero_step_timeout() {
        let err = GitPushReplayPlan::new(
            "/usr/bin/git",
            "/abs/bundle.pack",
            "/abs/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('e'),
            Vec::new(),
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, GitPushReplayPlanError::ZeroStepTimeout));
    }

    #[test]
    fn plan_allows_branch_creation_with_no_expected_remote_head() {
        let plan = sample_plan(
            "/usr/bin/git",
            "/abs/bundle.pack",
            "/abs/staging.git",
            sample_object_id('e'),
        );
        assert!(plan.expected_remote_head().is_none());
    }

    #[test]
    fn init_bare_command_carries_expected_argv_shape() {
        let plan = sample_plan(
            "/usr/local/bin/git",
            "/work/bundle.pack",
            "/work/staging.git",
            sample_object_id('f'),
        );
        let init = plan.init_bare_command();
        let args = init.display_args_lossy();
        assert_eq!(
            args,
            vec!["init", "--bare", "--quiet", "--", "/work/staging.git"]
        );
        assert!(init.required_secret_env().is_empty());
    }

    #[test]
    fn trailer_source_exposes_its_key() {
        let fixed = TrailerSource::Fixed {
            key: TrailerKey::new("X-Writ-Session").unwrap(),
            value: TrailerValue::new("abc-123").unwrap(),
        };
        let derived = TrailerSource::OriginalCommitSha {
            key: TrailerKey::new("X-Writ-Source-Commit").unwrap(),
        };
        assert_eq!(fixed.key().as_str(), "X-Writ-Session");
        assert_eq!(derived.key().as_str(), "X-Writ-Source-Commit");
    }

    #[test]
    fn trailer_key_accepts_conventional_shapes() {
        for raw in [
            "Co-authored-by",
            "Signed-off-by",
            "X-Writ-Session",
            "K9",
            "a",
        ] {
            let key = TrailerKey::new(raw).expect(raw);
            assert_eq!(key.as_str(), raw);
        }
    }

    #[test]
    fn trailer_key_rejects_empty() {
        assert_eq!(TrailerKey::new(""), Err(TrailerKeyError::Empty));
    }

    #[test]
    fn trailer_key_rejects_leading_digit_or_dash() {
        let leading_digit = TrailerKey::new("9-foo").unwrap_err();
        assert!(matches!(leading_digit, TrailerKeyError::InvalidStart(_)));
        let leading_dash = TrailerKey::new("-foo").unwrap_err();
        assert!(matches!(leading_dash, TrailerKeyError::InvalidStart(_)));
    }

    #[test]
    fn trailer_key_rejects_colon_space_and_other_bytes() {
        for raw in ["foo:", "foo bar", "foo_bar", "føø", "foo\n"] {
            let err = TrailerKey::new(raw).unwrap_err();
            assert!(
                matches!(err, TrailerKeyError::InvalidByte(_)),
                "expected InvalidByte for {raw:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn trailer_value_accepts_utf8_and_preserves_whitespace() {
        let value = TrailerValue::new("  Octocat <octocat@example.com>  ").unwrap();
        assert_eq!(value.as_str(), "  Octocat <octocat@example.com>  ");
        let utf8 = TrailerValue::new("Ångström <a@example.com>").unwrap();
        assert_eq!(utf8.as_str(), "Ångström <a@example.com>");
    }

    #[test]
    fn trailer_value_rejects_empty() {
        assert_eq!(TrailerValue::new(""), Err(TrailerValueError::Empty));
    }

    #[test]
    fn trailer_value_rejects_control_bytes() {
        for raw in ["line\nfeed", "carriage\rreturn", "nul\0byte"] {
            assert_eq!(
                TrailerValue::new(raw),
                Err(TrailerValueError::ContainsControlByte),
                "{raw:?} should be rejected",
            );
        }
    }

    fn valid_key_strategy() -> impl Strategy<Value = String> {
        // Pin a small finite generator: 1 leading ASCII letter, 0..=15
        // body bytes from the alnum+dash alphabet. Keeps shrinking
        // tractable without ceding coverage of the validation rule.
        let leading = "[A-Za-z]";
        let body = "[A-Za-z0-9-]{0,15}";
        (leading, body).prop_map(|(a, b)| format!("{a}{b}"))
    }

    fn valid_value_strategy() -> impl Strategy<Value = String> {
        // Reject the three control bytes; otherwise accept arbitrary
        // non-empty unicode. `prop_filter_map` keeps the constraint
        // visible at the strategy site.
        ".{1,32}".prop_filter_map("contains control bytes", |s| {
            if s.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
                None
            } else {
                Some(s)
            }
        })
    }

    proptest! {
        #[test]
        fn trailer_key_round_trips_for_valid_alphabet(raw in valid_key_strategy()) {
            let key = TrailerKey::new(raw.clone()).expect("strategy produces valid keys");
            prop_assert_eq!(key.as_str(), raw);
        }

        #[test]
        fn trailer_value_round_trips_for_valid_inputs(raw in valid_value_strategy()) {
            let value = TrailerValue::new(raw.clone()).expect("strategy produces valid values");
            prop_assert_eq!(value.as_str(), raw);
        }

        #[test]
        fn trailer_value_always_rejects_control_bytes(
            prefix in ".{0,8}",
            ctrl in prop::sample::select(vec!['\n', '\r', '\0']),
            suffix in ".{0,8}",
        ) {
            let raw = format!("{prefix}{ctrl}{suffix}");
            prop_assert_eq!(
                TrailerValue::new(raw),
                Err(TrailerValueError::ContainsControlByte),
            );
        }
    }

    // ---------- prepare_staging_repo executor tests -------------------

    /// Locate a real binary on PATH whose presence we assume in tests
    /// (mirrors the helper in `vm_git_bundle`). Fails the test loudly if
    /// missing rather than silently skipping, so CI never quietly drops
    /// coverage.
    fn required_test_tool(name: &str) -> PathBuf {
        let path = std::env::var_os("PATH").expect("PATH must be set in tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            match std::fs::metadata(&candidate) {
                Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 => {
                    return candidate;
                }
                _ => {}
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    /// Shell-quote a path so it survives the heredoc body unmodified.
    fn shell_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let mut quoted = String::with_capacity(raw.len() + 2);
        quoted.push('\'');
        for ch in raw.chars() {
            if ch == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(ch);
            }
        }
        quoted.push('\'');
        quoted
    }

    /// Fake-git stand-in: records every invocation to a log file and
    /// emulates `git init --bare --quiet -- <path>`. `exit_status` is
    /// substituted into the init branch so tests can force a non-zero
    /// exit without changing the rest of the script. Returns `(git_path,
    /// log_path)`.
    fn fake_git_for_init(dir: &TempDir, exit_status: u8) -> (PathBuf, PathBuf) {
        let git = dir.path().join("fake-git");
        let log = dir.path().join("fake-git.log");
        let shell = required_test_tool("sh");
        let mkdir = required_test_tool("mkdir");
        let script = format!(
            r#"#!{shell}
set -eu
log={log}
printf '%s' "$*" >> "$log"
printf '\n' >> "$log"
if [ "$1" = "init" ]; then
    [ "$2" = "--bare" ]
    [ "$3" = "--quiet" ]
    [ "$4" = "--" ]
    {mkdir} -p "$5"
    exit {exit_status}
fi
exit 42
"#,
            shell = shell.display(),
            log = shell_quote(&log),
            mkdir = shell_quote(&mkdir),
        );
        std::fs::write(&git, script).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        (git, log)
    }

    #[tokio::test]
    async fn prepare_staging_repo_runs_init_bare_against_fake_git() {
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("bundle.pack");
        std::fs::write(&bundle, b"bundle bytes").unwrap();
        let staging = dir.path().join("staging.git");
        let (git, log) = fake_git_for_init(&dir, 0);

        let plan = sample_plan(git, bundle, staging.clone(), sample_object_id('a'));
        let returned = prepare_staging_repo(&plan).await.expect("prepare succeeds");
        assert_eq!(returned, staging);

        let body = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly 1 git invocation, got {body:?}"
        );
        assert_eq!(
            lines[0],
            format!("init --bare --quiet -- {}", staging.display()),
        );
    }

    #[tokio::test]
    async fn prepare_staging_repo_rejects_preexisting_staging_repo() {
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("bundle.pack");
        std::fs::write(&bundle, b"bundle bytes").unwrap();
        let staging = dir.path().join("staging.git");
        std::fs::create_dir_all(&staging).unwrap();
        let (git, _) = fake_git_for_init(&dir, 0);

        let plan = sample_plan(git, bundle, staging.clone(), sample_object_id('b'));
        let err = prepare_staging_repo(&plan).await.unwrap_err();
        assert!(
            matches!(&err, GitPushReplayRunError::StagingRepoAlreadyExists(p) if p == &staging),
            "expected StagingRepoAlreadyExists, got {err:?}",
        );
    }

    #[tokio::test]
    async fn prepare_staging_repo_creates_staging_repo_with_private_permissions() {
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("bundle.pack");
        std::fs::write(&bundle, b"bundle bytes").unwrap();
        let staging = dir.path().join("staging.git");
        let (git, _) = fake_git_for_init(&dir, 0);

        let plan = sample_plan(git, bundle, staging.clone(), sample_object_id('c'));
        prepare_staging_repo(&plan).await.unwrap();

        let meta = std::fs::metadata(&staging).unwrap();
        assert!(meta.is_dir());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, REPLAY_BARE_REPO_MODE,
            "expected staging repo mode {:o}, got {:o}",
            REPLAY_BARE_REPO_MODE, mode,
        );
    }

    #[tokio::test]
    async fn prepare_staging_repo_surfaces_init_failure_with_correct_step() {
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("bundle.pack");
        std::fs::write(&bundle, b"bundle bytes").unwrap();
        let staging = dir.path().join("staging.git");
        // Force `git init --bare` to exit non-zero.
        let (git, _) = fake_git_for_init(&dir, 7);

        let plan = sample_plan(git, bundle, staging, sample_object_id('d'));
        let err = prepare_staging_repo(&plan).await.unwrap_err();
        match err {
            GitPushReplayRunError::Failed { step, .. } => {
                assert_eq!(step, GitPushReplayCommandStep::InitBareRepo);
            }
            other => panic!("expected Failed at InitBareRepo, got {other:?}"),
        }
    }
}
