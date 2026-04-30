//! VM-facing Git operations.
//!
//! This module is still pure planning: it validates VM clone requests and
//! describes the host-side commands needed to produce a Git bundle, but it
//! does not run `git` or mint credentials.
//!
//! [`RepoRef`] is the repo-wide "owner/name" shape. [`GitCloneRepo`] layers
//! GitHub-specific owner/name syntax on top because this endpoint always
//! targets GitHub HTTPS remotes.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::{CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef};

const DEFAULT_MIRROR_DIR_NAME: &str = "mirror.git";
const GITHUB_HTTPS_BASE: &str = "https://github.com";
pub const VM_GIT_CLONE_PATH: &str = "/v1/git/clone";
pub const GIT_BUNDLE_CONTENT_TYPE: &str = "application/x-git-bundle";
const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 3] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneRequest {
    repo: GitCloneRepo,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    git_ref: Option<GitCloneRef>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRepo(RepoRef);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRef(String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneErrorResponse {
    error: VmGitCloneErrorCode,
    message: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmGitCloneErrorCode {
    InvalidRequest,
    Denied,
    CloneFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCredentialBoundary {
    askpass_program: PathBuf,
    token_env: GitSecretEnvVar,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitSecretEnvVar(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundlePlan {
    git_program: PathBuf,
    request: VmGitCloneRequest,
    credential: GitCredentialBoundary,
    work_dir: PathBuf,
    mirror_dir: PathBuf,
    bundle_path: PathBuf,
    timeout: Duration,
    max_bundle_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCloneBundleCommands {
    clone_mirror: GitCommandInvocation,
    create_bundle: GitCommandInvocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommandInvocation {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<GitCommandEnv>,
    required_secret_env: Vec<GitSecretEnvVar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommandEnv {
    name: String,
    value: String,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitCloneRepoError {
    #[error("expected 'owner/name', got '{0}'")]
    Malformed(String),
    #[error(
        "GitHub owner must be 1-39 ASCII letters, digits, or hyphens, and cannot start or end with hyphen: {0}"
    )]
    InvalidOwner(String),
    #[error(
        "GitHub repository name must be 1-100 ASCII letters, digits, dots, underscores, or hyphens: {0}"
    )]
    InvalidName(String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitCloneRefError {
    #[error("Git ref must not be empty")]
    Empty,
    #[error("Git ref is too long; maximum is 255 bytes")]
    TooLong,
    #[error("Git ref must not start with '-'")]
    LeadingDash,
    #[error("Git ref must not start, end, or contain a double slash")]
    SlashPlacement,
    #[error("Git ref contains a forbidden sequence: {0}")]
    ForbiddenSequence(&'static str),
    #[error("Git ref contains a forbidden byte: {0:?}")]
    ForbiddenByte(char),
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
pub enum GitCloneBundlePlanError {
    #[error("{field} path must not be empty")]
    EmptyPath { field: &'static str },
    #[error("{field} path must be absolute: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("bundle path must not be inside the mirror repository: {0}")]
    BundleInsideMirror(PathBuf),
    #[error("clone timeout must be nonzero")]
    ZeroTimeout,
    #[error("maximum bundle size must be nonzero")]
    ZeroMaxBundleBytes,
}

impl VmGitCloneRequest {
    pub fn new(repo: GitCloneRepo, git_ref: Option<GitCloneRef>) -> Self {
        Self { repo, git_ref }
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn git_ref(&self) -> Option<&GitCloneRef> {
        self.git_ref.as_ref()
    }

    pub fn authorization_request(&self) -> CapabilityRequest {
        CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Read,
            repo: self.repo.as_repo_ref().clone(),
        })
    }
}

impl GitCloneRepo {
    pub fn new(repo: RepoRef) -> Result<Self, GitCloneRepoError> {
        validate_owner(&repo.owner)?;
        validate_repo_name(&repo.name)?;
        Ok(Self(repo))
    }

    pub fn as_repo_ref(&self) -> &RepoRef {
        &self.0
    }

    pub fn into_repo_ref(self) -> RepoRef {
        self.0
    }

    pub fn github_https_url(&self) -> String {
        format!("{GITHUB_HTTPS_BASE}/{}.git", self.0)
    }
}

impl std::fmt::Debug for GitCloneRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GitCloneRepo").field(&self.0).finish()
    }
}

impl std::fmt::Display for GitCloneRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for GitCloneRepo {
    type Err = GitCloneRepoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let repo: RepoRef = raw
            .parse()
            .map_err(|_| GitCloneRepoError::Malformed(raw.to_string()))?;
        Self::new(repo)
    }
}

impl Serialize for GitCloneRepo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitCloneRepo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl GitCloneRef {
    pub fn new(raw: impl Into<String>) -> Result<Self, GitCloneRefError> {
        let raw = raw.into();
        validate_git_ref(&raw)?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GitCloneRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GitCloneRef").field(&self.0).finish()
    }
}

impl std::fmt::Display for GitCloneRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for GitCloneRef {
    type Err = GitCloneRefError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl Serialize for GitCloneRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitCloneRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl VmGitCloneErrorResponse {
    pub fn new(error: VmGitCloneErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }

    pub fn error(&self) -> VmGitCloneErrorCode {
        self.error
    }

    pub fn message(&self) -> &str {
        &self.message
    }
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

impl GitCloneBundlePlan {
    pub fn new(
        git_program: impl Into<PathBuf>,
        request: VmGitCloneRequest,
        credential: GitCredentialBoundary,
        work_dir: impl Into<PathBuf>,
        bundle_path: impl Into<PathBuf>,
        timeout: Duration,
        max_bundle_bytes: u64,
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
        if max_bundle_bytes == 0 {
            return Err(GitCloneBundlePlanError::ZeroMaxBundleBytes);
        }

        let mirror_dir = work_dir.join(DEFAULT_MIRROR_DIR_NAME);
        // The executor slice must repeat this check after canonicalising the
        // created paths so symlinks cannot move the bundle into the mirror.
        if bundle_path.starts_with(&mirror_dir) {
            return Err(GitCloneBundlePlanError::BundleInsideMirror(bundle_path));
        }

        Ok(Self {
            git_program,
            request,
            credential,
            work_dir,
            mirror_dir,
            bundle_path,
            timeout,
            max_bundle_bytes,
        })
    }

    pub fn request(&self) -> &VmGitCloneRequest {
        &self.request
    }

    pub fn credential(&self) -> &GitCredentialBoundary {
        &self.credential
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn mirror_dir(&self) -> &Path {
        &self.mirror_dir
    }

    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_bundle_bytes(&self) -> u64 {
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

    fn clone_mirror_command(&self) -> GitCommandInvocation {
        GitCommandInvocation::new(
            self.git_program.clone(),
            [
                OsString::from("-c"),
                OsString::from("credential.helper="),
                OsString::from("-c"),
                OsString::from("credential.useHttpPath=true"),
                OsString::from("clone"),
                OsString::from("--mirror"),
                OsString::from("--"),
                OsString::from(self.request.repo.github_https_url()),
                self.mirror_dir.as_os_str().to_os_string(),
            ],
            self.clone_mirror_env(),
            vec![self.credential.token_env.clone()],
        )
    }

    fn create_bundle_command(&self) -> GitCommandInvocation {
        let mut args = vec![
            OsString::from("-C"),
            self.mirror_dir.as_os_str().to_os_string(),
            OsString::from("bundle"),
            OsString::from("create"),
            OsString::from("--"),
            self.bundle_path.as_os_str().to_os_string(),
        ];
        match self.request.git_ref() {
            Some(git_ref) => args.push(OsString::from(git_ref.as_str())),
            None => args.push(OsString::from("--all")),
        }
        GitCommandInvocation::new(
            self.git_program.clone(),
            args,
            clean_git_config_env(),
            vec![],
        )
    }

    fn clone_mirror_env(&self) -> Vec<GitCommandEnv> {
        let mut env = clean_git_config_env();
        env.push(GitCommandEnv::new("GIT_TERMINAL_PROMPT", "0"));
        env.push(GitCommandEnv::new(
            "GIT_ASKPASS",
            self.credential.askpass_program.display().to_string(),
        ));
        env
    }
}

impl GitCloneBundleCommands {
    pub fn clone_mirror(&self) -> &GitCommandInvocation {
        &self.clone_mirror
    }

    pub fn create_bundle(&self) -> &GitCommandInvocation {
        &self.create_bundle
    }

    pub fn all(&self) -> [&GitCommandInvocation; 2] {
        [&self.clone_mirror, &self.create_bundle]
    }
}

impl GitCommandInvocation {
    fn new(
        program: PathBuf,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        env: Vec<GitCommandEnv>,
        required_secret_env: Vec<GitSecretEnvVar>,
    ) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            env,
            required_secret_env,
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn env(&self) -> &[GitCommandEnv] {
        &self.env
    }

    pub fn required_secret_env(&self) -> &[GitSecretEnvVar] {
        &self.required_secret_env
    }

    pub fn display_args_lossy(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }
}

impl GitCommandEnv {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

fn validate_owner(owner: &str) -> Result<(), GitCloneRepoError> {
    if owner.is_empty()
        || owner.len() > 39
        || owner.starts_with('-')
        || owner.ends_with('-')
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(GitCloneRepoError::InvalidOwner(owner.to_string()));
    }
    Ok(())
}

fn validate_repo_name(name: &str) -> Result<(), GitCloneRepoError> {
    if name.is_empty()
        || name.len() > 100
        || matches!(name, "." | "..")
        || name.ends_with(".git")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(GitCloneRepoError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_git_ref(raw: &str) -> Result<(), GitCloneRefError> {
    if raw.is_empty() {
        return Err(GitCloneRefError::Empty);
    }
    if raw.len() > 255 {
        return Err(GitCloneRefError::TooLong);
    }
    if raw.starts_with('-') {
        return Err(GitCloneRefError::LeadingDash);
    }
    if raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        return Err(GitCloneRefError::SlashPlacement);
    }
    if raw.ends_with('.') {
        return Err(GitCloneRefError::ForbiddenSequence("."));
    }
    if raw == "@" {
        return Err(GitCloneRefError::ForbiddenSequence("@"));
    }
    for sequence in ["..", "@{"] {
        if raw.contains(sequence) {
            return Err(GitCloneRefError::ForbiddenSequence(sequence));
        }
    }
    for ch in raw.chars() {
        if ch.is_ascii_control()
            || ch.is_ascii_whitespace()
            || matches!(ch, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        {
            return Err(GitCloneRefError::ForbiddenByte(ch));
        }
        if !ch.is_ascii() {
            return Err(GitCloneRefError::ForbiddenByte(ch));
        }
    }
    for component in raw.split('/') {
        if component.starts_with('.') || component.ends_with(".lock") {
            return Err(GitCloneRefError::ForbiddenSequence(".lock"));
        }
    }
    Ok(())
}

fn clean_git_config_env() -> Vec<GitCommandEnv> {
    CLEAN_GIT_CONFIG_ENV
        .into_iter()
        .map(|(name, value)| GitCommandEnv::new(name, value))
        .collect()
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
mod tests {
    use super::*;
    use proptest::prelude::*;

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
            "/tmp/writ-clone.bundle",
            Duration::from_secs(30),
            64 * 1024 * 1024,
        )
        .unwrap()
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

    fn invalid_git_ref_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            "[A-Za-z0-9._/-]{0,40}".prop_map(|suffix| format!("-{suffix}")),
            "[A-Za-z0-9._-]{0,40}".prop_map(|suffix| format!("/{suffix}")),
            "[A-Za-z0-9._-]{0,40}".prop_map(|prefix| format!("{prefix}/")),
            "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}//x")),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}..x")),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}@{{x")),
            "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}/.hidden")),
            "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}.lock/x")),
            "[A-Za-z0-9_-]{0,20}".prop_map(|prefix| format!("{prefix}.")),
            Just("@".to_string()),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}:x")),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix} x")),
        ]
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
            "/tmp/writ-clone.bundle",
            Duration::from_secs(30),
            64 * 1024 * 1024,
        )
        .unwrap();
        let repo_url = clone_repo.github_https_url();
        let expected_ref = plan.request().git_ref().map(|r| r.as_str().to_string());
        (plan, repo_url, expected_ref)
    }

    proptest! {
        #[test]
        fn vm_clone_request_roundtrips_any_valid_generated_repo(
            owner in owner_strategy(),
            name in repo_name_strategy(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let clone_repo = GitCloneRepo::new(repo_ref.clone()).unwrap();
            let request = VmGitCloneRequest::new(clone_repo, None);

            let json = serde_json::to_string(&request).unwrap();
            let roundtrip: VmGitCloneRequest = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
            prop_assert_eq!(roundtrip, request);
        }

        #[test]
        fn git_ref_roundtrips_any_valid_generated_ref(raw in git_ref_strategy()) {
            let parsed = GitCloneRef::new(raw.clone()).unwrap();
            let reparsed: GitCloneRef = parsed.as_str().parse().unwrap();
            prop_assert_eq!(reparsed, parsed.clone());
            prop_assert_eq!(parsed.as_str(), raw);
        }

        #[test]
        fn generated_invalid_git_refs_are_rejected(raw in invalid_git_ref_strategy()) {
            prop_assert!(
                raw.parse::<GitCloneRef>().is_err(),
                "accepted invalid ref {raw:?}"
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
            prop_assert!(bundle_args.contains(&"/tmp/writ-clone.bundle".to_string()));
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
    }

    #[test]
    fn clone_request_with_ref_roundtrips_wire_shape() {
        let request = VmGitCloneRequest::new(
            repo("owner", "repo.name"),
            Some("feature/x".parse().unwrap()),
        );
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["repo"], "owner/repo.name");
        assert_eq!(value["ref"], "feature/x");
        assert_eq!(
            serde_json::from_value::<VmGitCloneRequest>(value).unwrap(),
            request
        );
    }

    #[test]
    fn malformed_repos_are_rejected_before_planning() {
        for raw in [
            "no-slash",
            "/repo",
            "owner/",
            "-owner/repo",
            "owner-/repo",
            "owner/repo name",
            "owner/..",
            "owner/foo.git",
            "owner/repo/path",
        ] {
            assert!(raw.parse::<GitCloneRepo>().is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn malformed_refs_are_rejected_before_planning() {
        for raw in [
            "",
            "-main",
            "/main",
            "main/",
            "feature//x",
            "feature..x",
            "feature@{1}",
            "branch.lock",
            "feature.lock/x",
            "feature/.hidden",
            "main.",
            "feature/x.",
            "@",
            "has space",
            "has:colon",
            "has*star",
            "unicodé",
        ] {
            assert!(raw.parse::<GitCloneRef>().is_err(), "accepted {raw:?}");
        }
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
                1,
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
                1,
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
                "/tmp/work/mirror.git/out.bundle",
                Duration::from_secs(1),
                1,
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
                "/tmp/out.bundle",
                Duration::ZERO,
                1,
            ),
            Err(GitCloneBundlePlanError::ZeroTimeout)
        );
        assert_eq!(
            GitCloneBundlePlan::new(
                "git",
                request(),
                credential(),
                "/tmp/work",
                "/tmp/out.bundle",
                Duration::from_secs(1),
                0,
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
                "/tmp/writ-clone.bundle",
                "--all",
            ]
        );
        assert_eq!(
            commands
                .clone_mirror()
                .required_secret_env()
                .iter()
                .map(GitSecretEnvVar::as_str)
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
            assert_eq!(env_value(command, "GIT_CONFIG_COUNT"), Some("0"));
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

    fn env_value<'a>(command: &'a GitCommandInvocation, name: &str) -> Option<&'a str> {
        command
            .env()
            .iter()
            .find(|env| env.name() == name)
            .map(GitCommandEnv::value)
    }

    #[test]
    fn bundle_command_uses_requested_ref_when_present() {
        let plan = GitCloneBundlePlan::new(
            "git",
            VmGitCloneRequest::new(repo("owner", "repo"), Some("release/v1".parse().unwrap())),
            credential(),
            "/tmp/work",
            "/tmp/out.bundle",
            Duration::from_secs(1),
            1,
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
                "/tmp/out.bundle",
                "release/v1",
            ]
        );
    }

    #[test]
    fn error_response_wire_shape_is_stable() {
        let response =
            VmGitCloneErrorResponse::new(VmGitCloneErrorCode::InvalidRequest, "bad repo");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["error"], "invalid_request");
        assert_eq!(value["message"], "bad repo");
        assert_eq!(
            serde_json::from_value::<VmGitCloneErrorResponse>(value).unwrap(),
            response
        );
    }

    #[test]
    fn authorization_request_grants_github_contents_read_scope() {
        match request().authorization_request() {
            CapabilityRequest::GitHub(GitHubRequest::Contents { access, repo }) => {
                assert_eq!(access, GitHubAccess::Read);
                assert_eq!(repo, RepoRef::from_str("smaug123/writ").unwrap());
            }
            other => panic!("unexpected capability: {other:?}"),
        }
    }

    #[test]
    fn clone_route_and_bundle_content_type_are_pinned() {
        assert_eq!(VM_GIT_CLONE_PATH, "/v1/git/clone");
        assert_eq!(GIT_BUNDLE_CONTENT_TYPE, "application/x-git-bundle");
    }
}
