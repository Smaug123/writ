//! Host-side Git bundle planning and execution for VM clone requests.
//!
//! The guest-visible request/response shapes live in [`crate::vm_git`]. This
//! module starts from those parsed wire types and describes or executes the
//! host commands needed to produce a private Git bundle. It does not mint
//! credentials.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;
use writ_core::byte_size::ByteSize;

use crate::clean_git::{
    self, CleanGitEnv, CleanGitError, CleanGitInvocation, clean_git_config_env,
};
use crate::vm_git::{GitCloneRepo, VmGitCloneRequest};

const DEFAULT_MIRROR_DIR_NAME: &str = "mirror.git";
pub const DEFAULT_GIT_CLONE_BASE_URL: &str = "https://github.com";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCredentialBoundary {
    askpass_program: PathBuf,
    token_env: GitSecretEnvVar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBaseUrl {
    url: reqwest::Url,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundleSource {
    request: VmGitCloneRequest,
    clone_base_url: GitCloneBaseUrl,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitSecretEnvVar(String);

/// Token value that is safe to pass as an environment variable value.
///
/// This deliberately does not constrain the token's alphabet beyond the OS
/// environment boundary: empty values and NUL bytes are invalid, every other
/// byte sequence that Rust can hold in a `String` is caller-owned secret
/// material.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitSecretValue(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundlePlan {
    git_program: PathBuf,
    source: GitCloneBundleSource,
    credential: GitCredentialBoundary,
    work_dir: PathBuf,
    mirror_dir: PathBuf,
    bundle_path: PathBuf,
    timeout: Duration,
    max_bundle_bytes: ByteSize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundleRunOutput {
    bundle_path: PathBuf,
    bundle_bytes: ByteSize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundleCommands {
    clone_mirror: CleanGitInvocation,
    create_bundle: CleanGitInvocation,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitSecretEnvVarError {
    #[error("secret environment variable name must not be empty")]
    Empty,
    #[error("secret environment variable name must start with ASCII letter or underscore: {0}")]
    InvalidStart(String),
    #[error(
        "secret environment variable name must contain only ASCII letters, digits, or underscores: {0}"
    )]
    InvalidByte(String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitSecretValueError {
    #[error("Git secret value must not be empty")]
    Empty,
    #[error("Git secret value must not contain NUL")]
    ContainsNul,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitCloneBundlePlanError {
    #[error("Git clone base URL must not be empty")]
    EmptyGitCloneBaseUrl,
    #[error("Git clone base URL {raw:?} is invalid: {message}")]
    InvalidGitCloneBaseUrl { raw: String, message: String },
    #[error("Git clone base URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedGitCloneBaseUrlScheme { raw: String, scheme: String },
    #[error("Git clone base URL must not contain embedded credentials: {0:?}")]
    GitCloneBaseUrlHasCredentials(String),
    #[error("Git clone base URL must not contain a query or fragment: {0:?}")]
    GitCloneBaseUrlHasQueryOrFragment(String),
    #[error("{field} path must not be empty")]
    EmptyPath { field: &'static str },
    #[error("{field} path must be absolute: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("bundle path must not be inside the mirror repository: {0}")]
    BundleInsideMirror(PathBuf),
    #[error(
        "bundle path must be a file inside the Git clone work directory, not the directory itself: {0}"
    )]
    BundlePathIsWorkDir(PathBuf),
    #[error("bundle path must be inside the Git clone work directory: {0}")]
    BundleOutsideWorkDir(PathBuf),
    #[error("clone timeout must be nonzero")]
    ZeroTimeout,
    #[error("maximum bundle size must be nonzero")]
    ZeroMaxBundleBytes,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GitCloneCommandStep {
    CloneMirror,
    CreateBundle,
}

#[derive(Debug, thiserror::Error)]
pub enum GitCloneBundleRunError {
    #[error("cannot create Git clone work directory {path}: {source}")]
    CreateWorkDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Git clone work directory already exists before clone run: {0}")]
    WorkDirAlreadyExists(PathBuf),
    #[error("cannot set Git clone work directory permissions for {path}: {source}")]
    SetWorkDirPermissions {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("bundle path already exists before Git clone run: {0}")]
    BundleAlreadyExists(PathBuf),
    #[error("bundle path must include a file name: {0}")]
    InvalidBundlePath(PathBuf),
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
    #[error("bundle path resolves inside the mirror repository: {0}")]
    BundleInsideMirror(PathBuf),
    #[error("bundle path resolves outside the Git clone work directory: {0}")]
    BundleEscapedWorkDir(PathBuf),
    /// The bundle target resolves *to* the work directory itself. Reachable
    /// through the pre-create check, which runs before the bundle exists: a
    /// symlinked parent can make an otherwise-nested target canonicalise back
    /// onto the work dir.
    #[error("bundle path resolves to the Git clone work directory itself: {0}")]
    BundleIsWorkDir(PathBuf),
    #[error("{step} command could not be spawned: {source}")]
    Spawn {
        step: GitCloneCommandStep,
        source: std::io::Error,
    },
    #[error("{step} command wait failed: {source}")]
    Wait {
        step: GitCloneCommandStep,
        source: std::io::Error,
    },
    #[error("{step} command timed out after {timeout:?}")]
    TimedOut {
        step: GitCloneCommandStep,
        timeout: Duration,
    },
    #[error("{step} command failed with status {status}: {stderr}")]
    Failed {
        step: GitCloneCommandStep,
        status: ExitStatus,
        /// git's captured stderr, tail-capped and secret-redacted by
        /// `clean_git` — the real reason (auth, DNS, missing repo) behind the
        /// exit status.
        stderr: String,
    },
    #[error("{step} command did not expose a child process id")]
    MissingProcessId { step: GitCloneCommandStep },
    #[error("{step} child process id {pid} cannot be represented as a process group id")]
    InvalidProcessId { step: GitCloneCommandStep, pid: u32 },
    #[error("{step} process group {pgid} could not be killed after Git child exit: {source}")]
    KillProcessGroup {
        step: GitCloneCommandStep,
        pgid: libc::pid_t,
        source: std::io::Error,
    },
    #[error(
        "{step} command wrote more than the {cap}-byte stdout cap; the process group was killed"
    )]
    StdoutCapExceeded {
        step: GitCloneCommandStep,
        cap: usize,
    },
    #[error("cannot inspect bundle {path}: {source}")]
    InspectBundle {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("bundle path is not a regular file: {0}")]
    BundleNotAFile(PathBuf),
    #[error("bundle is too large: {bytes} bytes exceeds limit {max_bundle_bytes}")]
    BundleTooLarge {
        bytes: ByteSize,
        max_bundle_bytes: ByteSize,
    },
}

impl GitCredentialBoundary {
    pub fn new(
        askpass_program: impl Into<PathBuf>,
        token_env: GitSecretEnvVar,
    ) -> Result<Self, GitCloneBundlePlanError> {
        let askpass_program = askpass_program.into();
        require_absolute_path("askpass_program", &askpass_program)?;
        Ok(Self {
            askpass_program,
            token_env,
        })
    }

    pub fn askpass_program(&self) -> &Path {
        &self.askpass_program
    }

    pub fn token_env(&self) -> &GitSecretEnvVar {
        &self.token_env
    }
}

impl GitCloneBaseUrl {
    pub fn github() -> Self {
        Self::parse(DEFAULT_GIT_CLONE_BASE_URL)
            .expect("default Git clone base URL is a valid HTTPS URL")
    }

    pub fn parse(raw: impl AsRef<str>) -> Result<Self, GitCloneBundlePlanError> {
        let raw = raw.as_ref();
        if raw.is_empty() {
            return Err(GitCloneBundlePlanError::EmptyGitCloneBaseUrl);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| {
            GitCloneBundlePlanError::InvalidGitCloneBaseUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(GitCloneBundlePlanError::UnsupportedGitCloneBaseUrlScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GitCloneBundlePlanError::GitCloneBaseUrlHasCredentials(
                raw.to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(GitCloneBundlePlanError::GitCloneBaseUrlHasQueryOrFragment(
                raw.to_string(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self { url })
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn repo_url(&self, repo: &GitCloneRepo) -> String {
        let repo_ref = repo.as_repo_ref();
        let mut url = self.url.clone();
        let path = format!("{}{}/{}.git", url.path(), repo_ref.owner, repo_ref.name);
        url.set_path(&path);
        url.to_string()
    }
}

impl GitCloneBundleSource {
    pub fn github(request: VmGitCloneRequest) -> Self {
        Self::new(request, GitCloneBaseUrl::github())
    }

    pub fn new(request: VmGitCloneRequest, clone_base_url: GitCloneBaseUrl) -> Self {
        Self {
            request,
            clone_base_url,
        }
    }

    pub fn request(&self) -> &VmGitCloneRequest {
        &self.request
    }

    pub fn clone_base_url(&self) -> &GitCloneBaseUrl {
        &self.clone_base_url
    }
}

impl GitSecretEnvVar {
    pub fn new(raw: impl Into<String>) -> Result<Self, GitSecretEnvVarError> {
        let raw = raw.into();
        validate_secret_env_var(&raw)?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GitSecretEnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GitSecretEnvVar").field(&self.0).finish()
    }
}

impl std::fmt::Display for GitSecretEnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl GitSecretValue {
    pub fn new(raw: impl Into<String>) -> Result<Self, GitSecretValueError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(GitSecretValueError::Empty);
        }
        if raw.contains('\0') {
            return Err(GitSecretValueError::ContainsNul);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GitSecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GitSecretValue(<redacted>)")
    }
}

impl GitCloneBundleRunOutput {
    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    pub fn bundle_bytes(&self) -> ByteSize {
        self.bundle_bytes
    }
}

impl std::fmt::Display for GitCloneCommandStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitCloneCommandStep::CloneMirror => f.write_str("clone mirror"),
            GitCloneCommandStep::CreateBundle => f.write_str("create bundle"),
        }
    }
}

impl GitCloneBundlePlan {
    pub fn new(
        git_program: impl Into<PathBuf>,
        request: VmGitCloneRequest,
        credential: GitCredentialBoundary,
        work_dir: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        timeout: Duration,
        max_bundle_bytes: ByteSize,
    ) -> Result<Self, GitCloneBundlePlanError> {
        Self::new_with_source(
            git_program,
            GitCloneBundleSource::github(request),
            credential,
            work_dir,
            bundle_path,
            timeout,
            max_bundle_bytes,
        )
    }

    pub fn new_with_source(
        git_program: impl Into<PathBuf>,
        source: GitCloneBundleSource,
        credential: GitCredentialBoundary,
        work_dir: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        timeout: Duration,
        max_bundle_bytes: ByteSize,
    ) -> Result<Self, GitCloneBundlePlanError> {
        let git_program = git_program.into();
        let work_dir = work_dir.into();
        let bundle_path = bundle_path.into();
        require_non_empty_path("git_program", &git_program)?;
        require_absolute_path("work_dir", &work_dir)?;
        require_absolute_path("bundle_path", &bundle_path)?;
        if timeout.is_zero() {
            return Err(GitCloneBundlePlanError::ZeroTimeout);
        }
        if max_bundle_bytes.is_zero() {
            return Err(GitCloneBundlePlanError::ZeroMaxBundleBytes);
        }

        let work_dir = normalize_absolute_path_lexically(work_dir);
        let bundle_path = normalize_absolute_path_lexically(bundle_path);
        let mirror_dir = work_dir.join(DEFAULT_MIRROR_DIR_NAME);
        // Lexical evidence: these paths need not exist yet, so they cannot be
        // canonicalised. The executor re-runs *this same predicate* against
        // canonicalised paths once they do (see `validate_bundle_location`), so
        // a symlink cannot alias its way past the check after the fact.
        let boundary = BundleBoundary {
            work_dir: &work_dir,
            mirror_dir: &mirror_dir,
        };
        if let Err(violation) = boundary.check(&bundle_path) {
            return Err(violation.into_plan_error(bundle_path));
        }

        Ok(Self {
            git_program,
            source,
            credential,
            work_dir,
            mirror_dir,
            bundle_path,
            timeout,
            max_bundle_bytes,
        })
    }

    pub fn request(&self) -> &VmGitCloneRequest {
        self.source.request()
    }

    pub fn credential(&self) -> &GitCredentialBoundary {
        &self.credential
    }

    pub fn clone_base_url(&self) -> &GitCloneBaseUrl {
        self.source.clone_base_url()
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn mirror_dir(&self) -> &Path {
        &self.mirror_dir
    }

    pub fn git_program(&self) -> &Path {
        &self.git_program
    }

    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_bundle_bytes(&self) -> ByteSize {
        self.max_bundle_bytes
    }

    pub fn commands(&self) -> GitCloneBundleCommands {
        let clone_mirror = self.clone_mirror_command();
        let create_bundle = self.create_bundle_command();
        GitCloneBundleCommands {
            clone_mirror,
            create_bundle,
        }
    }

    fn clone_mirror_command(&self) -> CleanGitInvocation {
        CleanGitInvocation::new(
            self.git_program.clone(),
            [
                OsString::from("-c"),
                OsString::from("credential.helper="),
                OsString::from("-c"),
                OsString::from("credential.useHttpPath=true"),
                OsString::from("clone"),
                OsString::from("--mirror"),
                OsString::from("--"),
                OsString::from(self.clone_base_url().repo_url(self.request().repo())),
                self.mirror_dir.as_os_str().to_os_string(),
            ],
            self.clone_mirror_env(),
            vec![self.credential.token_env.as_str().to_string()],
        )
    }

    fn create_bundle_command(&self) -> CleanGitInvocation {
        let mut args = vec![
            OsString::from("-C"),
            self.mirror_dir.as_os_str().to_os_string(),
            OsString::from("bundle"),
            OsString::from("create"),
            OsString::from("--"),
            self.bundle_path.as_os_str().to_os_string(),
        ];
        match self.request().git_ref() {
            Some(git_ref) => args.push(OsString::from(git_ref.as_str())),
            None => args.push(OsString::from("--all")),
        }
        CleanGitInvocation::new(
            self.git_program.clone(),
            args,
            clean_git_config_env(),
            vec![],
        )
    }

    fn clone_mirror_env(&self) -> Vec<CleanGitEnv> {
        let mut env = clean_git_config_env();
        env.push(CleanGitEnv::new("GIT_TERMINAL_PROMPT", "0"));
        env.push(CleanGitEnv::new(
            "GIT_ASKPASS",
            self.credential.askpass_program.display().to_string(),
        ));
        env
    }
}

/// Execute a clone/bundle plan.
///
/// This is the imperative shell for [`GitCloneBundlePlan`]. It creates the
/// plan's work directory but otherwise leaves path cleanup to the caller; the
/// caller should supply unique temporary paths and remove them after streaming
/// or discarding the bundle.
pub async fn run_git_clone_bundle(
    plan: &GitCloneBundlePlan,
    secret: &GitSecretValue,
) -> Result<GitCloneBundleRunOutput, GitCloneBundleRunError> {
    create_private_work_dir(plan).await?;
    reject_existing_bundle(plan).await?;

    let commands = plan.commands();
    run_clone_invocation(
        GitCloneCommandStep::CloneMirror,
        commands.clone_mirror(),
        plan.timeout(),
        secret,
    )
    .await?;
    reject_bundle_inside_canonical_mirror(plan).await?;
    run_clone_invocation(
        GitCloneCommandStep::CreateBundle,
        commands.create_bundle(),
        plan.timeout(),
        secret,
    )
    .await?;
    verify_bundle_output(plan).await
}

impl GitCloneBundleCommands {
    pub(crate) fn clone_mirror(&self) -> &CleanGitInvocation {
        &self.clone_mirror
    }

    pub(crate) fn create_bundle(&self) -> &CleanGitInvocation {
        &self.create_bundle
    }

    #[cfg(test)]
    pub(crate) fn all(&self) -> [&CleanGitInvocation; 2] {
        [&self.clone_mirror, &self.create_bundle]
    }
}

async fn reject_existing_bundle(plan: &GitCloneBundlePlan) -> Result<(), GitCloneBundleRunError> {
    match tokio::fs::symlink_metadata(plan.bundle_path()).await {
        Ok(_) => Err(GitCloneBundleRunError::BundleAlreadyExists(
            plan.bundle_path().to_path_buf(),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(GitCloneBundleRunError::InspectBundle {
            path: plan.bundle_path().to_path_buf(),
            source,
        }),
    }
}

async fn create_private_work_dir(plan: &GitCloneBundlePlan) -> Result<(), GitCloneBundleRunError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(plan.work_dir()) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(GitCloneBundleRunError::WorkDirAlreadyExists(
                plan.work_dir().to_path_buf(),
            ));
        }
        Err(source) => {
            return Err(GitCloneBundleRunError::CreateWorkDir {
                path: plan.work_dir().to_path_buf(),
                source,
            });
        }
    }
    // mode(0o700) is subject to the process umask; set_permissions makes the
    // postcondition explicit for private clone artifacts.
    std::fs::set_permissions(plan.work_dir(), std::fs::Permissions::from_mode(0o700)).map_err(
        |source| GitCloneBundleRunError::SetWorkDirPermissions {
            path: plan.work_dir().to_path_buf(),
            source,
        },
    )
}

async fn run_clone_invocation(
    step: GitCloneCommandStep,
    invocation: &CleanGitInvocation,
    timeout: Duration,
    secret: &GitSecretValue,
) -> Result<(), GitCloneBundleRunError> {
    clean_git::run_clean_git(invocation, timeout, Some(secret.as_str()))
        .await
        .map_err(|err| translate_clean_git_error(step, err))
}

fn translate_clean_git_error(
    step: GitCloneCommandStep,
    err: CleanGitError,
) -> GitCloneBundleRunError {
    match err {
        CleanGitError::GitProgramNotFound(p) => GitCloneBundleRunError::GitProgramNotFound(p),
        CleanGitError::Canonicalize {
            field,
            path,
            source,
        } => GitCloneBundleRunError::Canonicalize {
            field,
            path,
            source,
        },
        CleanGitError::Spawn(source) => GitCloneBundleRunError::Spawn { step, source },
        CleanGitError::Wait(source) => GitCloneBundleRunError::Wait { step, source },
        CleanGitError::TimedOut(timeout) => GitCloneBundleRunError::TimedOut { step, timeout },
        CleanGitError::Failed { status, stderr } => GitCloneBundleRunError::Failed {
            step,
            status,
            stderr,
        },
        CleanGitError::MissingProcessId => GitCloneBundleRunError::MissingProcessId { step },
        CleanGitError::InvalidProcessId(pid) => {
            GitCloneBundleRunError::InvalidProcessId { step, pid }
        }
        CleanGitError::KillProcessGroup { pgid, source } => {
            GitCloneBundleRunError::KillProcessGroup { step, pgid, source }
        }
        CleanGitError::StdoutCapExceeded { cap } => {
            GitCloneBundleRunError::StdoutCapExceeded { step, cap }
        }
    }
}

async fn reject_bundle_inside_canonical_mirror(
    plan: &GitCloneBundlePlan,
) -> Result<(), GitCloneBundleRunError> {
    let target = canonical_bundle_target(plan).await?;
    validate_bundle_location(plan, &target).await
}

async fn canonical_bundle_target(
    plan: &GitCloneBundlePlan,
) -> Result<PathBuf, GitCloneBundleRunError> {
    let parent = plan.bundle_path().parent().ok_or_else(|| {
        GitCloneBundleRunError::InvalidBundlePath(plan.bundle_path().to_path_buf())
    })?;
    let file_name = plan.bundle_path().file_name().ok_or_else(|| {
        GitCloneBundleRunError::InvalidBundlePath(plan.bundle_path().to_path_buf())
    })?;
    let parent = canonicalize_path("bundle_parent", parent).await?;
    Ok(parent.join(file_name))
}

async fn verify_bundle_output(
    plan: &GitCloneBundlePlan,
) -> Result<GitCloneBundleRunOutput, GitCloneBundleRunError> {
    let metadata = tokio::fs::symlink_metadata(plan.bundle_path())
        .await
        .map_err(|source| GitCloneBundleRunError::InspectBundle {
            path: plan.bundle_path().to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(GitCloneBundleRunError::BundleNotAFile(
            plan.bundle_path().to_path_buf(),
        ));
    }
    let bytes = ByteSize::from_bytes(metadata.len());
    if bytes > plan.max_bundle_bytes() {
        return Err(GitCloneBundleRunError::BundleTooLarge {
            bytes,
            max_bundle_bytes: plan.max_bundle_bytes(),
        });
    }

    let bundle = canonicalize_path("bundle_path", plan.bundle_path()).await?;
    validate_bundle_location(plan, &bundle).await?;

    Ok(GitCloneBundleRunOutput {
        bundle_path: plan.bundle_path().to_path_buf(),
        bundle_bytes: bytes,
    })
}

async fn canonicalize_path(
    field: &'static str,
    path: &Path,
) -> Result<PathBuf, GitCloneBundleRunError> {
    tokio::fs::canonicalize(path)
        .await
        .map_err(|source| GitCloneBundleRunError::Canonicalize {
            field,
            path: path.to_path_buf(),
            source,
        })
}

/// Where a bundle is allowed to sit: under the broker-owned work dir, and not
/// under the mirror inside it.
///
/// This is the *policy*, defined once. It is asked twice — lexically at plan
/// time, when the paths need not exist yet, and against freshly-canonicalised
/// paths at run time, when a symlink could otherwise have aliased the bundle
/// somewhere else since. Those two differ only in the *evidence* they are given;
/// having them differ in the question as well is what previously let the checks
/// drift out of step, with no reader able to tell whether they still agreed.
struct BundleBoundary<'a> {
    work_dir: &'a Path,
    mirror_dir: &'a Path,
}

/// How a bundle path fails [`BundleBoundary::check`]. Deliberately phase-neutral:
/// each phase maps it to its own error type, so the predicate stays one
/// definition while the diagnostics stay specific about when it was asked.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BundleBoundaryViolation {
    IsWorkDir,
    OutsideWorkDir,
    InsideMirror,
}

impl BundleBoundary<'_> {
    fn check(&self, bundle: &Path) -> Result<(), BundleBoundaryViolation> {
        if bundle == self.work_dir {
            return Err(BundleBoundaryViolation::IsWorkDir);
        }
        if !bundle.starts_with(self.work_dir) {
            return Err(BundleBoundaryViolation::OutsideWorkDir);
        }
        if bundle.starts_with(self.mirror_dir) {
            return Err(BundleBoundaryViolation::InsideMirror);
        }
        Ok(())
    }
}

impl BundleBoundaryViolation {
    fn into_plan_error(self, bundle: PathBuf) -> GitCloneBundlePlanError {
        match self {
            Self::IsWorkDir => GitCloneBundlePlanError::BundlePathIsWorkDir(bundle),
            Self::OutsideWorkDir => GitCloneBundlePlanError::BundleOutsideWorkDir(bundle),
            Self::InsideMirror => GitCloneBundlePlanError::BundleInsideMirror(bundle),
        }
    }

    fn into_run_error(self, bundle: PathBuf) -> GitCloneBundleRunError {
        match self {
            Self::IsWorkDir => GitCloneBundleRunError::BundleIsWorkDir(bundle),
            Self::OutsideWorkDir => GitCloneBundleRunError::BundleEscapedWorkDir(bundle),
            Self::InsideMirror => GitCloneBundleRunError::BundleInsideMirror(bundle),
        }
    }
}

/// Ask [`BundleBoundary`] the run-time question, against canonical paths.
///
/// `bundle` must already be canonical, and the directories are canonicalised
/// here, so a symlink cannot alias its way past the check.
async fn validate_bundle_location(
    plan: &GitCloneBundlePlan,
    bundle: &Path,
) -> Result<(), GitCloneBundleRunError> {
    let work_dir = canonicalize_path("work_dir", plan.work_dir()).await?;
    let mirror_dir = canonicalize_path("mirror_dir", plan.mirror_dir()).await?;
    BundleBoundary {
        work_dir: &work_dir,
        mirror_dir: &mirror_dir,
    }
    .check(bundle)
    .map_err(|violation| violation.into_run_error(bundle.to_path_buf()))
}

fn normalize_absolute_path_lexically(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn validate_secret_env_var(raw: &str) -> Result<(), GitSecretEnvVarError> {
    let Some(first) = raw.bytes().next() else {
        return Err(GitSecretEnvVarError::Empty);
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(GitSecretEnvVarError::InvalidStart(raw.to_string()));
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(GitSecretEnvVarError::InvalidByte(raw.to_string()));
    }
    Ok(())
}

fn require_non_empty_path(field: &'static str, path: &Path) -> Result<(), GitCloneBundlePlanError> {
    if path.as_os_str().is_empty() {
        return Err(GitCloneBundlePlanError::EmptyPath { field });
    }
    Ok(())
}

fn require_absolute_path(field: &'static str, path: &Path) -> Result<(), GitCloneBundlePlanError> {
    require_non_empty_path(field, path)?;
    if !path.is_absolute() {
        return Err(GitCloneBundlePlanError::RelativePath {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn github_https_url(repo: &GitCloneRepo) -> String {
    GitCloneBaseUrl::github().repo_url(repo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean_git::resolve_program_for_clean_env;
    use crate::core::RepoRef;
    use crate::process_supervisor::is_executable_file;
    use crate::vm_git::GitCloneRef;
    use proptest::prelude::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const TEST_GIT_TIMEOUT: Duration = Duration::from_secs(30);

    fn repo(owner: &str, name: &str) -> GitCloneRepo {
        format!("{owner}/{name}").parse().unwrap()
    }

    fn request() -> VmGitCloneRequest {
        VmGitCloneRequest::new(repo("smaug123", "writ"), None)
    }

    fn credential() -> GitCredentialBoundary {
        GitCredentialBoundary::new(
            "/usr/local/libexec/writ-git-askpass",
            GitSecretEnvVar::new("WRIT_GITHUB_TOKEN").unwrap(),
        )
        .unwrap()
    }

    fn plan() -> GitCloneBundlePlan {
        GitCloneBundlePlan::new(
            "git",
            request(),
            credential(),
            "/tmp/writ-clone-work",
            "/tmp/writ-clone-work/out.bundle",
            Duration::from_secs(30),
            ByteSize::mib(64),
        )
        .unwrap()
    }

    fn plan_with_paths(
        git_program: impl Into<PathBuf>,
        work_dir: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        timeout: Duration,
        max_bundle_bytes: ByteSize,
    ) -> GitCloneBundlePlan {
        GitCloneBundlePlan::new(
            git_program,
            request(),
            credential(),
            work_dir,
            bundle_path,
            timeout,
            max_bundle_bytes,
        )
        .unwrap()
    }

    fn git_secret() -> GitSecretValue {
        GitSecretValue::new("super-secret-token").unwrap()
    }

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn required_test_tool(name: &str) -> PathBuf {
        let path = std::env::var_os("PATH")
            .unwrap_or_else(|| panic!("PATH must contain {name} for vm_git tests"));
        for dir in std::env::split_paths(&path) {
            let candidate = if dir.is_absolute() {
                dir.join(name)
            } else {
                std::env::current_dir().unwrap().join(dir).join(name)
            };
            match std::fs::metadata(&candidate) {
                Ok(metadata) if is_executable_file(&metadata) => {
                    // Preserve symlink spelling: bash changes behaviour when
                    // invoked through its `sh` symlink.
                    return candidate;
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => panic!("failed to inspect {}: {err}", candidate.display()),
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    fn fake_git_program(
        dir: &TempDir,
        clone_extra: &str,
        bundle_extra: &str,
    ) -> (PathBuf, PathBuf) {
        let git = dir.path().join("fake-git");
        let log = dir.path().join("fake-git.log");
        let shell = required_test_tool("sh");
        let mkdir = shell_quote(&required_test_tool("mkdir"));
        let script = format!(
            r#"#!{shell}
set -eu
log={log}
cwd=$(pwd)
printf '%s|%s|%s|%s|%s|%s|%s|%s=%s\n' "$cwd" "${{GIT_CONFIG_NOSYSTEM-unset}}" "${{GIT_CONFIG_GLOBAL-unset}}" "${{GIT_CONFIG_COUNT-unset}}" "${{WRIT_GITHUB_TOKEN-unset}}" "${{HOME-unset}}" "${{PATH+set}}" "${{GIT_CONFIG_KEY_0-unset}}" "${{GIT_CONFIG_VALUE_0-unset}}" >> "$log"
if [ "$1" = "-c" ]; then
    [ "$2" = "credential.helper=" ]
    [ "$3" = "-c" ]
    [ "$4" = "credential.useHttpPath=true" ]
    [ "$5" = "clone" ]
    [ "$6" = "--mirror" ]
    [ "$7" = "--" ]
    [ "$8" = "https://github.com/smaug123/writ.git" ]
    {mkdir} -p "$9"
{clone_extra}
    exit 0
fi
if [ "$1" = "-C" ]; then
    [ "$3" = "bundle" ]
    [ "$4" = "create" ]
    [ "$5" = "--" ]
    printf 'fake-bundle' > "$6"
{bundle_extra}
    exit 0
fi
exit 42
"#,
            shell = shell.display(),
            log = shell_quote(&log),
            mkdir = mkdir,
            clone_extra = clone_extra,
            bundle_extra = bundle_extra,
        );
        std::fs::write(&git, script).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        (git, log)
    }

    /// How long [`wait_for_path_or_finished`] waits for the marker before
    /// declaring a hang. Deliberately generous: the marker is written by a
    /// freshly-`exec`ed descendant process whose startup (subprocess spawn
    /// and OS scheduling of the new process) can be delayed by many seconds
    /// under peak parallel-test load — the machine is oversubscribed while
    /// ~1500 tests run, many spawning their own subprocesses. The previous
    /// 10s bound was occasionally too tight and flaked. Since the wait
    /// returns the instant the marker appears, a large bound costs nothing
    /// on healthy runs and only delays the failure of a genuine hang.
    const MARKER_WAIT_BUDGET: Duration = Duration::from_secs(60);

    /// Poll until `path` appears, returning the instant it does. Fails fast
    /// if `handle` finishes first (the descendant was never spawned), and
    /// bounds the wait by [`MARKER_WAIT_BUDGET`] (wall-clock, so timer slop
    /// under load cannot shorten it) so a genuine hang surfaces as a
    /// failure with diagnostics rather than blocking forever.
    async fn wait_for_path_or_finished<T>(path: &Path, handle: &tokio::task::JoinHandle<T>) {
        let start = std::time::Instant::now();
        loop {
            if path.exists() {
                return;
            }
            assert!(
                !handle.is_finished(),
                "task finished before {} appeared",
                path.display()
            );
            if start.elapsed() >= MARKER_WAIT_BUDGET {
                let parent = path.parent().unwrap();
                let listing: Vec<String> = std::fs::read_dir(parent)
                    .map(|rd| {
                        rd.filter_map(|e| {
                            e.ok().map(|e| e.file_name().to_string_lossy().into_owned())
                        })
                        .collect()
                    })
                    .unwrap_or_default();
                panic!(
                    "timed out waiting for {} after {:?}; handle.is_finished()={}; \
                     sibling files: {:?}",
                    path.display(),
                    start.elapsed(),
                    handle.is_finished(),
                    listing
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn ascii_alnum() -> impl Strategy<Value = char> {
        prop_oneof![
            (b'a'..=b'z').prop_map(char::from),
            (b'A'..=b'Z').prop_map(char::from),
            (b'0'..=b'9').prop_map(char::from),
        ]
    }

    fn owner_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            ascii_alnum().prop_map(|ch| ch.to_string()),
            (
                ascii_alnum(),
                prop::collection::vec(prop_oneof![ascii_alnum(), Just('-')], 0..37,),
                ascii_alnum(),
            )
                .prop_map(|(first, middle, last)| {
                    std::iter::once(first)
                        .chain(middle)
                        .chain(std::iter::once(last))
                        .collect()
                }),
        ]
    }

    fn repo_name_strategy() -> impl Strategy<Value = String> {
        (
            ascii_alnum(),
            prop::collection::vec(prop_oneof![ascii_alnum(), Just('_'), Just('-')], 0..99),
        )
            .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
    }

    fn ref_component_strategy() -> impl Strategy<Value = String> {
        (
            prop_oneof![ascii_alnum(), Just('_')],
            prop::collection::vec(prop_oneof![ascii_alnum(), Just('_'), Just('-')], 0..20),
        )
            .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
    }

    fn git_ref_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(ref_component_strategy(), 1..5).prop_map(|components| {
            let mut raw = components.join("/");
            raw.truncate(255);
            raw
        })
    }

    fn git_clone_base_url_strategy() -> impl Strategy<Value = (String, String)> {
        (
            prop_oneof![Just("http"), Just("https")],
            prop::collection::vec(
                prop_oneof![
                    (b'a'..=b'z').prop_map(char::from),
                    (b'0'..=b'9').prop_map(char::from),
                ],
                1..16,
            ),
            prop::collection::vec(ref_component_strategy(), 0..4),
        )
            .prop_map(|(scheme, host_chars, path_components)| {
                let host = host_chars.into_iter().collect::<String>();
                let path = if path_components.is_empty() {
                    String::new()
                } else {
                    format!("/{}", path_components.join("/"))
                };
                let raw = format!("{scheme}://{host}.example{path}");
                let expected_prefix = format!("{scheme}://{host}.example{path}/");
                (raw, expected_prefix)
            })
    }

    fn token_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                (b'a'..=b'f').prop_map(char::from),
                (b'0'..=b'9').prop_map(char::from),
            ],
            1..96,
        )
        .prop_map(|chars| format!("[secret:{}]", chars.into_iter().collect::<String>()))
    }

    fn descendant_survivor_script(dir: &TempDir) -> PathBuf {
        let script = dir.path().join("descendant-survivor");
        let shell = required_test_tool("sh");
        let sleep = shell_quote(&required_test_tool("sleep"));
        // `$1.started` is touched before the sleep so a caller can wait
        // for the descendant to actually exist (and thus be in the
        // parent's process group) before triggering cleanup, instead of
        // relying on a fixed-duration sleep that races on contended
        // hosts. `$1` ("survived") is written only if the sleep
        // completes without being killed.
        std::fs::write(
            &script,
            format!(
                "#!{}\n# Ignore HUP so only process-group SIGKILL can satisfy the cleanup test.\ntrap '' HUP\nprintf started > \"$1.started\"\n{} 1\nprintf survived > \"$1\"\n",
                shell.display(),
                sleep,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn plan_for(
        owner: String,
        name: String,
        git_ref: Option<String>,
    ) -> (GitCloneBundlePlan, String, Option<String>) {
        let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
        let clone_repo = GitCloneRepo::new(repo_ref).unwrap();
        let git_ref = git_ref.map(|raw| GitCloneRef::new(raw).unwrap());
        let request = VmGitCloneRequest::new(clone_repo.clone(), git_ref);
        let plan = GitCloneBundlePlan::new(
            "git",
            request,
            credential(),
            "/tmp/writ-clone-work",
            "/tmp/writ-clone-work/out.bundle",
            Duration::from_secs(30),
            ByteSize::mib(64),
        )
        .unwrap();
        let repo_url = github_https_url(&clone_repo);
        let expected_ref = plan.request().git_ref().map(|r| r.as_str().to_string());
        (plan, repo_url, expected_ref)
    }

    /// Path components that stay inside one directory level: no separators, no
    /// `.`/`..`, so a generated path's shape is exactly what it reads as.
    fn path_segment_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(vec!['a', 'b', 'm', '-', '_', '1']),
            1..6,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("segment must not be a relative-path component", |s| {
            s != "." && s != ".."
        })
    }

    /// An absolute path under `/w`, sometimes reaching into the mirror and
    /// sometimes escaping the work dir entirely, so the generator exercises
    /// every arm of the predicate rather than just the accepting one.
    fn bundle_candidate_strategy() -> impl Strategy<Value = PathBuf> {
        prop::collection::vec(path_segment_strategy(), 0..4).prop_flat_map(|tail| {
            prop::sample::select(vec!["/w", "/w/mirror.git", "/elsewhere", "/"]).prop_map(
                move |root| {
                    let mut path = PathBuf::from(root);
                    for segment in &tail {
                        path.push(segment);
                    }
                    path
                },
            )
        })
    }

    proptest! {
        /// The predicate's contract, stated independently of how it is
        /// implemented. Both phases — lexical at plan time, canonical at run
        /// time — ask exactly this, so pinning it here is what stops the two
        /// drifting apart again.
        #[test]
        fn bundle_boundary_admits_exactly_the_paths_it_promises(
            bundle in bundle_candidate_strategy(),
        ) {
            let work_dir = PathBuf::from("/w");
            let mirror_dir = work_dir.join(DEFAULT_MIRROR_DIR_NAME);
            let boundary = BundleBoundary {
                work_dir: &work_dir,
                mirror_dir: &mirror_dir,
            };

            let inside_work_dir = bundle.starts_with(&work_dir) && bundle != work_dir;
            let inside_mirror = bundle.starts_with(&mirror_dir);
            let should_admit = inside_work_dir && !inside_mirror;

            match boundary.check(&bundle) {
                Ok(()) => prop_assert!(
                    should_admit,
                    "admitted {bundle:?}, which is not strictly under {work_dir:?} outside {mirror_dir:?}",
                ),
                Err(violation) => {
                    prop_assert!(!should_admit, "rejected admissible {bundle:?} as {violation:?}");
                    // The reported reason must be the true one, not merely *a*
                    // reason: an operator reading "inside the mirror" for a path
                    // that is nowhere near it would be misled.
                    let expected = if bundle == work_dir {
                        BundleBoundaryViolation::IsWorkDir
                    } else if !bundle.starts_with(&work_dir) {
                        BundleBoundaryViolation::OutsideWorkDir
                    } else {
                        BundleBoundaryViolation::InsideMirror
                    };
                    prop_assert_eq!(violation, expected, "wrong reason for {:?}", bundle);
                }
            }
        }

        /// Whatever the predicate rejects, both phases reject — and each reports
        /// it in its own vocabulary. This is the anti-drift property: the two
        /// phases differ in the evidence they are given, never in the question.
        #[test]
        fn both_phases_map_every_violation_to_their_own_error(
            bundle in bundle_candidate_strategy(),
        ) {
            let work_dir = PathBuf::from("/w");
            let mirror_dir = work_dir.join(DEFAULT_MIRROR_DIR_NAME);
            let boundary = BundleBoundary {
                work_dir: &work_dir,
                mirror_dir: &mirror_dir,
            };
            let Err(violation) = boundary.check(&bundle) else {
                return Ok(());
            };
            let plan_error = violation.into_plan_error(bundle.clone());
            let run_error = violation.into_run_error(bundle.clone());
            prop_assert_eq!(
                matches!(plan_error, GitCloneBundlePlanError::BundleInsideMirror(_)),
                matches!(run_error, GitCloneBundleRunError::BundleInsideMirror(_)),
                "phases disagree on whether {:?} is a mirror escape",
                bundle,
            );
        }

        #[test]
        fn plan_argv_contains_only_expected_dynamic_inputs(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            git_ref in prop::option::of(git_ref_strategy()),
            token in token_strategy(),
        ) {
            let (plan, repo_url, expected_ref) = plan_for(owner, name, git_ref);
            let commands = plan.commands();
            let clone_args = commands.clone_mirror().display_args_lossy();
            let bundle_args = commands.create_bundle().display_args_lossy();

            prop_assert!(clone_args.contains(&repo_url));
            prop_assert!(clone_args.contains(&"/tmp/writ-clone-work/mirror.git".to_string()));
            prop_assert!(bundle_args.contains(&"/tmp/writ-clone-work/mirror.git".to_string()));
            prop_assert!(bundle_args.contains(&"/tmp/writ-clone-work/out.bundle".to_string()));
            match expected_ref {
                Some(raw_ref) => prop_assert!(bundle_args.contains(&raw_ref)),
                None => prop_assert!(bundle_args.contains(&"--all".to_string())),
            }

            for command in commands.all() {
                let debug = format!("{command:?}");
                prop_assert!(!debug.contains(&token), "debug leaked token {token:?}: {debug}");
                for arg in command.display_args_lossy() {
                    prop_assert!(!arg.contains(&token), "argv leaked token {token:?}: {arg:?}");
                }
            }
            let plan_debug = format!("{plan:?}");
            prop_assert!(!plan_debug.contains(&token), "plan debug leaked token {token:?}: {plan_debug}");
        }

        #[test]
        fn clone_base_url_is_the_only_repo_url_prefix(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            (base_raw, expected_prefix) in git_clone_base_url_strategy(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let clone_repo = GitCloneRepo::new(repo_ref).unwrap();
            let base = GitCloneBaseUrl::parse(&base_raw).unwrap();
            let expected_url = format!("{expected_prefix}{owner}/{name}.git");

            prop_assert_eq!(base.repo_url(&clone_repo), expected_url.clone());

            let plan = GitCloneBundlePlan::new_with_source(
                "git",
                GitCloneBundleSource::new(VmGitCloneRequest::new(clone_repo, None), base),
                credential(),
                "/tmp/writ-clone-work",
                "/tmp/writ-clone-work/out.bundle",
                Duration::from_secs(30),
                ByteSize::mib(64),
            ).unwrap();
            let clone_args = plan.commands().clone_mirror().display_args_lossy();
            prop_assert!(clone_args.contains(&expected_url));
            prop_assert!(!clone_args.contains(&github_https_url(plan.request().repo())));
        }
    }

    #[test]
    fn clone_base_url_rejects_unsafe_shapes() {
        assert!(matches!(
            GitCloneBaseUrl::parse(""),
            Err(GitCloneBundlePlanError::EmptyGitCloneBaseUrl)
        ));
        assert!(matches!(
            GitCloneBaseUrl::parse("github.com"),
            Err(GitCloneBundlePlanError::InvalidGitCloneBaseUrl { .. })
        ));
        assert!(matches!(
            GitCloneBaseUrl::parse("ssh://github.com"),
            Err(GitCloneBundlePlanError::UnsupportedGitCloneBaseUrlScheme { scheme, .. })
                if scheme == "ssh"
        ));
        assert!(matches!(
            GitCloneBaseUrl::parse("https://user:token@github.com"),
            Err(GitCloneBundlePlanError::GitCloneBaseUrlHasCredentials(_))
        ));
        assert!(matches!(
            GitCloneBaseUrl::parse("https://github.com?owner=o"),
            Err(GitCloneBundlePlanError::GitCloneBaseUrlHasQueryOrFragment(
                _
            ))
        ));
        assert!(matches!(
            GitCloneBaseUrl::parse("https://github.com#repos"),
            Err(GitCloneBundlePlanError::GitCloneBaseUrlHasQueryOrFragment(
                _
            ))
        ));
    }

    #[test]
    fn secret_env_var_is_parsed_not_assumed() {
        assert!(GitSecretEnvVar::new("WRIT_GITHUB_TOKEN").is_ok());
        for raw in ["", "1TOKEN", "TOKEN-NAME", "TOKEN NAME"] {
            assert!(GitSecretEnvVar::new(raw).is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn plan_rejects_malformed_paths_and_limits() {
        assert_eq!(
            GitCredentialBoundary::new("relative-askpass", GitSecretEnvVar::new("TOKEN").unwrap()),
            Err(GitCloneBundlePlanError::RelativePath {
                field: "askpass_program",
                path: PathBuf::from("relative-askpass"),
            })
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "relative-work",
                "/tmp/out.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::RelativePath {
                field: "work_dir",
                path: PathBuf::from("relative-work"),
            })
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "relative.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::RelativePath {
                field: "bundle_path",
                path: PathBuf::from("relative.bundle"),
            })
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/out.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::BundleOutsideWorkDir(
                PathBuf::from("/tmp/out.bundle")
            ))
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/work",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::BundlePathIsWorkDir(PathBuf::from(
                "/tmp/work"
            )))
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/work/../out.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::BundleOutsideWorkDir(
                PathBuf::from("/tmp/out.bundle")
            ))
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/work/mirror.git/out.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::BundleInsideMirror(PathBuf::from(
                "/tmp/work/mirror.git/out.bundle"
            )))
        );

        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/work/out.bundle",
                Duration::ZERO,
                ByteSize::from_bytes(1),
            ),
            Err(GitCloneBundlePlanError::ZeroTimeout)
        );
        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/work/out.bundle",
                Duration::from_secs(1),
                ByteSize::from_bytes(0),
            ),
            Err(GitCloneBundlePlanError::ZeroMaxBundleBytes)
        );
    }

    #[test]
    fn plan_describes_clone_and_bundle_commands_without_credentials_in_argv() {
        let token = "ghs_this_must_not_appear";
        let plan = plan();
        let commands = plan.commands();

        let clone_args = commands.clone_mirror().display_args_lossy();
        assert_eq!(
            clone_args,
            vec![
                "-c",
                "credential.helper=",
                "-c",
                "credential.useHttpPath=true",
                "clone",
                "--mirror",
                "--",
                "https://github.com/smaug123/writ.git",
                "/tmp/writ-clone-work/mirror.git",
            ]
        );
        assert_eq!(
            commands.create_bundle().display_args_lossy(),
            vec![
                "-C",
                "/tmp/writ-clone-work/mirror.git",
                "bundle",
                "create",
                "--",
                "/tmp/writ-clone-work/out.bundle",
                "--all",
            ]
        );
        assert_eq!(
            commands
                .clone_mirror()
                .required_secret_env()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["WRIT_GITHUB_TOKEN"]
        );
        assert!(
            commands
                .clone_mirror()
                .env()
                .iter()
                .any(|env| env.name() == "GIT_ASKPASS")
        );
        for command in commands.all() {
            assert_eq!(env_value(command, "GIT_CONFIG_NOSYSTEM"), Some("1"));
            assert_eq!(env_value(command, "GIT_CONFIG_GLOBAL"), Some("/dev/null"));
            assert_eq!(env_value(command, "GIT_CONFIG_COUNT"), Some("2"));
            assert_eq!(env_value(command, "HOME"), Some("/dev/null"));
            // The mirror clone and the bundle build must not leave a detached
            // `git maintenance` behind: `clone_local` walks the source
            // `objects/pack/`, which is exactly what raced such a process in
            // CI.
            assert_eq!(
                env_value(command, "GIT_CONFIG_KEY_0"),
                Some("maintenance.auto")
            );
            assert_eq!(env_value(command, "GIT_CONFIG_VALUE_0"), Some("false"));
        }

        for command in commands.all() {
            assert!(
                !format!("{command:?}").contains(token),
                "debug leaked token in {command:?}"
            );
            for arg in command.display_args_lossy() {
                assert!(!arg.contains(token), "argv leaked token in {arg:?}");
            }
        }
        assert!(!format!("{plan:?}").contains(token));
    }

    fn env_value<'a>(command: &'a CleanGitInvocation, name: &str) -> Option<&'a str> {
        command
            .env()
            .iter()
            .find(|env| env.name() == name)
            .map(CleanGitEnv::value)
    }

    #[tokio::test]
    async fn executor_runs_fake_git_with_clean_env_and_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (git, log) = fake_git_program(&dir, "", "");
        let work = dir.path().join("work");
        let bundle = work.join("out.bundle");
        let plan = plan_with_paths(git, &work, &bundle, TEST_GIT_TIMEOUT, ByteSize::kib(1));

        let output = run_git_clone_bundle(&plan, &git_secret()).await.unwrap();

        assert_eq!(output.bundle_path(), bundle);
        assert_eq!(
            output.bundle_bytes(),
            ByteSize::from_bytes("fake-bundle".len() as u64)
        );
        let work_mode = std::fs::metadata(&work).unwrap().permissions().mode() & 0o777;
        assert_eq!(work_mode, 0o700);
        let log = std::fs::read_to_string(log).unwrap();
        let lines = log.lines().collect::<Vec<_>>();
        // The shebang shell may synthesize PATH even though the executor
        // cleared the parent environment; cwd, HOME, Git config, and token
        // scope are the load-bearing assertions here.
        //
        // The trailing field is the strongest evidence available anywhere that
        // the auto-maintenance suppression *arrives*: unlike the static
        // assertions on `CleanGitInvocation`, this is what a really-spawned
        // child really saw. `clone --mirror` walks the source `objects/pack/`,
        // which is exactly what raced a detached `git maintenance` in CI, so
        // this executor is the one that most needs it.
        assert_eq!(
            lines,
            vec![
                "/|1|/dev/null|2|super-secret-token|/dev/null|set|maintenance.auto=false",
                "/|1|/dev/null|2|unset|/dev/null|set|maintenance.auto=false",
            ]
        );
    }

    #[tokio::test]
    async fn executor_rejects_preexisting_work_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git_program(&dir, "", "");
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let plan = plan_with_paths(
            git,
            &work,
            work.join("out.bundle"),
            TEST_GIT_TIMEOUT,
            ByteSize::kib(1),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(err, GitCloneBundleRunError::WorkDirAlreadyExists(ref path) if path == &work),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn executable_check_uses_the_calling_users_permission_class() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let owned_file = dir.path().join("owned-program");
        std::fs::write(&owned_file, "#!/bin/sh\n").unwrap();

        std::fs::set_permissions(&owned_file, std::fs::Permissions::from_mode(0o001)).unwrap();
        assert!(
            !is_executable_file(&std::fs::metadata(&owned_file).unwrap()),
            "owner without owner-execute must not be accepted via world-execute"
        );

        std::fs::set_permissions(&owned_file, std::fs::Permissions::from_mode(0o100)).unwrap();
        assert!(is_executable_file(&std::fs::metadata(&owned_file).unwrap()));
    }

    #[tokio::test]
    async fn absolute_git_program_is_canonicalized_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git_program(&dir, "", "");
        let link = dir.path().join("git-link");
        std::os::unix::fs::symlink(&git, &link).unwrap();

        assert_eq!(
            resolve_program_for_clean_env(&link).await.unwrap(),
            std::fs::canonicalize(&git).unwrap()
        );
    }

    #[tokio::test]
    async fn executor_rejects_canonical_bundle_path_inside_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let link = work.join("link-to-mirror");
        let ln = shell_quote(&required_test_tool("ln"));
        let clone_extra = format!("{ln} -s \"$9\" {}\n", shell_quote(&link));
        let (git, _) = fake_git_program(&dir, &clone_extra, "");
        let plan = plan_with_paths(
            git,
            &work,
            link.join("out.bundle"),
            TEST_GIT_TIMEOUT,
            ByteSize::kib(1),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(err, GitCloneBundleRunError::BundleInsideMirror(_)),
            "unexpected error: {err:?}"
        );
        assert!(!plan.bundle_path().exists());
    }

    #[tokio::test]
    async fn executor_rejects_canonical_bundle_path_outside_work_dir() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let outside = dir.path().join("outside");
        let link = work.join("link-out");
        let mkdir = shell_quote(&required_test_tool("mkdir"));
        let ln = shell_quote(&required_test_tool("ln"));
        let clone_extra = format!(
            "{mkdir} -p {}\n{ln} -s {} {}\n",
            shell_quote(&outside),
            shell_quote(&outside),
            shell_quote(&link)
        );
        let (git, _) = fake_git_program(&dir, &clone_extra, "");
        let plan = plan_with_paths(
            git,
            &work,
            link.join("out.bundle"),
            TEST_GIT_TIMEOUT,
            ByteSize::kib(1),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(err, GitCloneBundleRunError::BundleEscapedWorkDir(_)),
            "unexpected error: {err:?}"
        );
        assert!(!outside.join("out.bundle").exists());
    }

    /// A nested bundle path whose parent is replaced, during the clone, by a
    /// symlink that resolves back onto the work dir. The pre-create check runs
    /// before the bundle exists, so this reaches the boundary predicate with a
    /// target *equal* to the work dir — the arm that would otherwise have been
    /// dismissed as unreachable and reported as a plain escape.
    #[tokio::test]
    async fn executor_rejects_a_bundle_target_that_resolves_onto_the_work_dir() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        // `work/up` becomes a symlink to the work dir's *parent*, so the
        // bundle path `work/up/work` has a parent that canonicalises to that
        // parent — and joining the final component "work" lands exactly on the
        // work dir itself.
        let up = work.join("up");
        let ln = shell_quote(&required_test_tool("ln"));
        let clone_extra = format!("{ln} -s {} {}\n", shell_quote(dir.path()), shell_quote(&up));
        let (git, _) = fake_git_program(&dir, &clone_extra, "");
        // Lexically this is a nested path with no `..` component, so plan-time
        // validation admits it; only the canonical pass can see where it lands.
        let plan = plan_with_paths(
            git,
            &work,
            up.join("work"),
            TEST_GIT_TIMEOUT,
            ByteSize::kib(1),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(err, GitCloneBundleRunError::BundleIsWorkDir(_)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn preflight_rejects_preexisting_dangling_bundle_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git_program(&dir, "", "");
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let bundle = work.join("out.bundle");
        let target = work.join("missing-target");
        std::os::unix::fs::symlink(&target, &bundle).unwrap();
        let plan = plan_with_paths(git, &work, &bundle, TEST_GIT_TIMEOUT, ByteSize::kib(1));

        let err = reject_existing_bundle(&plan).await.unwrap_err();

        assert!(
            matches!(err, GitCloneBundleRunError::BundleAlreadyExists(ref path) if path == &bundle),
            "unexpected error: {err:?}"
        );
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn executor_times_out_stuck_git_process() {
        let dir = tempfile::tempdir().unwrap();
        let survivor = descendant_survivor_script(&dir);
        let survivor_marker = dir.path().join("descendant-survived");
        let clone_extra = format!(
            "{} {} &\nwait\n",
            shell_quote(&survivor),
            shell_quote(&survivor_marker)
        );
        let (git, _) = fake_git_program(&dir, &clone_extra, "");
        let work = dir.path().join("work");
        let plan = plan_with_paths(
            git,
            &work,
            work.join("out.bundle"),
            Duration::from_millis(250),
            ByteSize::kib(1),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                GitCloneBundleRunError::TimedOut {
                    step: GitCloneCommandStep::CloneMirror,
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !survivor_marker.exists(),
            "background descendant survived process-group timeout cleanup"
        );
    }

    #[tokio::test]
    async fn executor_kills_process_group_when_future_is_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let survivor = descendant_survivor_script(&dir);
        let survivor_marker = dir.path().join("descendant-survived");
        let survivor_started_marker = dir.path().join("descendant-survived.started");
        let clone_extra = format!(
            "{} {} &\nwait\n",
            shell_quote(&survivor),
            shell_quote(&survivor_marker)
        );
        let (git, _log) = fake_git_program(&dir, &clone_extra, "");
        let work = dir.path().join("work");
        let plan = plan_with_paths(
            git,
            &work,
            work.join("out.bundle"),
            Duration::from_secs(30),
            ByteSize::kib(1),
        );
        let secret = git_secret();

        let handle = tokio::spawn(async move { run_git_clone_bundle(&plan, &secret).await });
        // Wait for the descendant to *actually* exist (and inherit the
        // child's process group) before triggering cleanup. The
        // previous fixed-duration sleep raced on contended hosts: if
        // the shell hadn't reached `${survivor} &` by the time the
        // abort fired, the descendant was forked *after* the
        // process-group SIGKILL and survived.
        wait_for_path_or_finished(&survivor_started_marker, &handle).await;
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());

        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !survivor_marker.exists(),
            "background descendant survived process-group cleanup after future cancellation"
        );
    }

    #[tokio::test]
    async fn executor_kills_descendants_after_successful_git_process() {
        let dir = tempfile::tempdir().unwrap();
        let survivor = descendant_survivor_script(&dir);
        let survivor_marker = dir.path().join("descendant-survived");
        let clone_extra = format!(
            "{} {} &\n",
            shell_quote(&survivor),
            shell_quote(&survivor_marker)
        );
        let (git, _) = fake_git_program(&dir, &clone_extra, "");
        let work = dir.path().join("work");
        let plan = plan_with_paths(
            git,
            &work,
            work.join("out.bundle"),
            TEST_GIT_TIMEOUT,
            ByteSize::kib(1),
        );

        run_git_clone_bundle(&plan, &git_secret()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !survivor_marker.exists(),
            "background descendant survived process-group cleanup after successful child exit"
        );
    }

    #[tokio::test]
    async fn executor_rejects_oversized_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git_program(&dir, "", "");
        let work = dir.path().join("work");
        let plan = plan_with_paths(
            git,
            &work,
            work.join("out.bundle"),
            TEST_GIT_TIMEOUT,
            ByteSize::from_bytes(4),
        );

        let err = run_git_clone_bundle(&plan, &git_secret())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                GitCloneBundleRunError::BundleTooLarge {
                    bytes,
                    max_bundle_bytes,
                } if bytes == ByteSize::of("fake-bundle".len())
                    && max_bundle_bytes == ByteSize::from_bytes(4)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn git_secret_value_is_redacted_and_rejects_invalid_values() {
        let secret = GitSecretValue::new("token").unwrap();
        assert_eq!(secret.as_str(), "token");
        assert_eq!(format!("{secret:?}"), "GitSecretValue(<redacted>)");
        assert_eq!(GitSecretValue::new(""), Err(GitSecretValueError::Empty));
        assert_eq!(
            GitSecretValue::new("has\0nul"),
            Err(GitSecretValueError::ContainsNul)
        );
    }

    #[test]
    fn bundle_command_uses_requested_ref_when_present() {
        let plan = GitCloneBundlePlan::new(
            "git",
            VmGitCloneRequest::new(repo("owner", "repo"), Some("release/v1".parse().unwrap())),
            credential(),
            "/tmp/work",
            "/tmp/work/out.bundle",
            Duration::from_secs(1),
            ByteSize::from_bytes(1),
        )
        .unwrap();

        assert_eq!(
            plan.commands().create_bundle().display_args_lossy(),
            vec![
                "-C",
                "/tmp/work/mirror.git",
                "bundle",
                "create",
                "--",
                "/tmp/work/out.bundle",
                "release/v1",
            ]
        );
    }
}
