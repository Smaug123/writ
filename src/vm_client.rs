//! Guest-side client for the VM HTTP broker.
//!
//! This is the small command surface intended to live inside the agent VM.
//! It consumes the daemon-injected `WRIT_BROKER_URL` / `WRIT_BROKER_TOKEN`
//! environment variables and talks to the host broker without ever receiving
//! GitHub credentials.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use reqwest::Url;

use crate::agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunStreamUpload,
    VmAgentRunConfigResponse, VmAgentRunOutcomeUpload, vm_agent_run_config_path,
    vm_agent_run_outcome_path,
};
use crate::bearer::is_bearer_token_byte;
use crate::process_spawn;
use crate::vm_git::{
    DEFAULT_DEVSHELL_ATTR, DEFAULT_WORKSPACE_BRANCH, GIT_BUNDLE_CONTENT_TYPE, GitCloneRef,
    GitCloneRepo, VM_GIT_CLONE_PATH, VmGitCloneErrorResponse, VmGitCloneRequest, WorkspaceWarmMode,
    default_workspace_destination, nix_develop_command_args,
};

pub const VM_BROKER_URL_ENV: &str = "WRIT_BROKER_URL";
pub const VM_BROKER_TOKEN_ENV: &str = "WRIT_BROKER_TOKEN";
pub const DEFAULT_VM_CLIENT_MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmClientConfig {
    broker_url: Url,
    bearer_token: VmBrokerToken,
    max_bundle_bytes: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VmBrokerToken(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmGitCloneCommand {
    request: VmGitCloneRequest,
    destination: PathBuf,
    git_program: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmWorkspaceInitCommand {
    repo: GitCloneRepo,
    destination: PathBuf,
    warm: WorkspaceWarmMode,
    git_program: PathBuf,
    nix_program: PathBuf,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmGitCloneStep {
    Clone,
    Init,
    Fetch,
    Checkout,
    RemoteAdd,
    CheckoutBranch,
    SetUpstream,
    Status,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmWorkspaceWarmStep {
    FlakeMetadata,
    DevShell,
}

#[derive(Debug, thiserror::Error)]
pub enum VmGitCloneCommandError {
    #[error("destination path must not be empty")]
    EmptyDestination,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmWorkspaceInitCommandError {
    #[error("workspace destination path must not be empty")]
    EmptyDestination,
}

#[derive(Debug, thiserror::Error)]
pub enum VmClientConfigError {
    #[error("missing required VM broker environment variable {0}")]
    MissingEnv(&'static str),
    #[error("VM broker URL must not contain a query or fragment: {0}")]
    BrokerUrlHasQueryOrFragment(String),
    #[error("VM broker URL must use http or https, got scheme {scheme:?}: {raw}")]
    UnsupportedBrokerUrlScheme { raw: String, scheme: String },
    #[error("invalid VM broker URL {raw:?}: {parse_error}")]
    InvalidBrokerUrl { raw: String, parse_error: String },
    #[error("VM broker token must not be empty")]
    EmptyToken,
    #[error("VM broker token contains a byte that is not valid in an HTTP bearer token")]
    InvalidToken,
    #[error("maximum Git bundle size must be greater than zero")]
    EmptyMaxBundleBytes,
}

#[derive(Debug, thiserror::Error)]
pub enum VmClientError {
    #[error("VM broker request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("VM broker returned HTTP {status}: {message}")]
    BrokerHttp { status: u16, message: String },
    #[error("VM broker returned content type {actual:?}, expected {expected}")]
    UnexpectedContentType {
        actual: Option<String>,
        expected: &'static str,
    },
    #[error(
        "VM broker returned a {bytes}-byte Git bundle, exceeding the {max_bundle_bytes}-byte limit"
    )]
    BundleTooLarge { bytes: u64, max_bundle_bytes: u64 },
    #[error("destination path already exists: {0:?}")]
    DestinationAlreadyExists(PathBuf),
    #[error("{operation} {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{step} git command could not be spawned: {source}")]
    GitSpawn {
        step: VmGitCloneStep,
        source: std::io::Error,
    },
    #[error("{step} git command failed with status {status}: {stderr}")]
    GitFailed {
        step: VmGitCloneStep,
        status: ExitStatus,
        stderr: String,
    },
    #[error("{step} command could not be spawned: {source}")]
    NixSpawn {
        step: VmWorkspaceWarmStep,
        source: std::io::Error,
    },
    #[error("{step} command failed with status {status}: {stderr}")]
    NixFailed {
        step: VmWorkspaceWarmStep,
        status: ExitStatus,
        stderr: String,
    },
    #[error("workspace checkout is dirty after bootstrap: {status}")]
    WorkspaceDirty { status: String },
}

struct TempBundle {
    path: PathBuf,
}

impl VmClientConfig {
    pub fn new(
        broker_url: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, VmClientConfigError> {
        let raw_url = broker_url.into();
        let bearer_token = VmBrokerToken::new(bearer_token)?;
        let broker_url = parse_broker_url(&raw_url)?;
        Ok(Self {
            broker_url,
            bearer_token,
            max_bundle_bytes: DEFAULT_VM_CLIENT_MAX_BUNDLE_BYTES,
        })
    }

    pub fn broker_url(&self) -> &Url {
        &self.broker_url
    }

    pub fn bearer_token(&self) -> &VmBrokerToken {
        &self.bearer_token
    }

    pub fn max_bundle_bytes(&self) -> u64 {
        self.max_bundle_bytes
    }

    pub fn with_max_bundle_bytes(
        mut self,
        max_bundle_bytes: u64,
    ) -> Result<Self, VmClientConfigError> {
        if max_bundle_bytes == 0 {
            return Err(VmClientConfigError::EmptyMaxBundleBytes);
        }
        self.max_bundle_bytes = max_bundle_bytes;
        Ok(self)
    }

    fn endpoint(&self, path: &str) -> Url {
        let relative = path.strip_prefix('/').unwrap_or(path);
        self.broker_url
            .join(relative)
            .expect("validated broker URL must join relative VM HTTP paths")
    }
}

impl VmBrokerToken {
    pub fn new(raw: impl Into<String>) -> Result<Self, VmClientConfigError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(VmClientConfigError::EmptyToken);
        }
        if !raw.bytes().all(is_bearer_token_byte) {
            return Err(VmClientConfigError::InvalidToken);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for VmBrokerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VmBrokerToken(<redacted>)")
    }
}

impl VmGitCloneCommand {
    pub fn new(
        repo: GitCloneRepo,
        git_ref: Option<GitCloneRef>,
        destination: Option<PathBuf>,
        git_program: impl Into<PathBuf>,
    ) -> Result<Self, VmGitCloneCommandError> {
        let destination = match destination {
            Some(path) => path,
            None => PathBuf::from(repo.as_repo_ref().name.clone()),
        };
        if destination.as_os_str().is_empty() {
            return Err(VmGitCloneCommandError::EmptyDestination);
        }
        Ok(Self {
            request: VmGitCloneRequest::new(repo, git_ref),
            destination,
            git_program: git_program.into(),
        })
    }

    pub fn request(&self) -> &VmGitCloneRequest {
        &self.request
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    pub fn git_program(&self) -> &Path {
        &self.git_program
    }
}

impl VmWorkspaceInitCommand {
    pub fn new(
        repo: GitCloneRepo,
        destination: Option<PathBuf>,
        warm: WorkspaceWarmMode,
        git_program: impl Into<PathBuf>,
        nix_program: impl Into<PathBuf>,
    ) -> Result<Self, VmWorkspaceInitCommandError> {
        let destination = match destination {
            Some(path) => path,
            None => default_workspace_destination(&repo),
        };
        if destination.as_os_str().is_empty() {
            return Err(VmWorkspaceInitCommandError::EmptyDestination);
        }
        Ok(Self {
            repo,
            destination,
            warm,
            git_program: git_program.into(),
            nix_program: nix_program.into(),
        })
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    pub fn warm(&self) -> WorkspaceWarmMode {
        self.warm
    }

    pub fn git_program(&self) -> &Path {
        &self.git_program
    }

    pub fn nix_program(&self) -> &Path {
        &self.nix_program
    }
}

pub async fn get_session_json(config: &VmClientConfig) -> Result<serde_json::Value, VmClientError> {
    let response = reqwest::Client::new()
        .get(config.endpoint("/v1/session"))
        .bearer_auth(config.bearer_token().as_str())
        .send()
        .await?;
    let response = require_success(response).await?;
    response
        .json::<serde_json::Value>()
        .await
        .map_err(VmClientError::from)
}

pub async fn fetch_agent_run_config(
    config: &VmClientConfig,
    run_id: AgentRunId,
) -> Result<(AgentPrompt, String), VmClientError> {
    let response = reqwest::Client::new()
        .get(config.endpoint(&vm_agent_run_config_path(run_id)))
        .bearer_auth(config.bearer_token().as_str())
        .send()
        .await?;
    let response = require_success(response).await?;
    require_content_type(&response, "application/json")?;
    response
        .json::<VmAgentRunConfigResponse>()
        .await
        .map(VmAgentRunConfigResponse::into_parts)
        .map_err(VmClientError::from)
}

pub async fn upload_agent_run_outcome(
    config: &VmClientConfig,
    outcome: &AgentRunOutcome,
) -> Result<(), VmClientError> {
    let upload = VmAgentRunOutcomeUpload {
        run_id: outcome.run_id,
        status: outcome.status.clone(),
        exit_code: outcome.exit_code,
        stdout: agent_run_stream_upload(&outcome.stdout)?,
        stderr: agent_run_stream_upload(&outcome.stderr)?,
    };
    let response = reqwest::Client::new()
        .post(config.endpoint(&vm_agent_run_outcome_path(outcome.run_id)))
        .bearer_auth(config.bearer_token().as_str())
        .json(&upload)
        .send()
        .await?;
    require_success(response).await?;
    Ok(())
}

pub async fn clone_from_broker(
    config: &VmClientConfig,
    command: &VmGitCloneCommand,
) -> Result<PathBuf, VmClientError> {
    let bundle = fetch_git_clone_bundle(config, command.request()).await?;
    clone_bundle_with_git(
        command.git_program(),
        command.request().git_ref(),
        command.destination(),
        &bundle,
    )?;
    Ok(command.destination().to_path_buf())
}

pub async fn init_workspace_from_broker(
    config: &VmClientConfig,
    command: &VmWorkspaceInitCommand,
) -> Result<PathBuf, VmClientError> {
    // This is the one-shot `writ-vm` CLI path. The HTTP fetch is async, but
    // the subsequent Git and Nix subprocesses intentionally run synchronously
    // because this process has no other work to schedule.
    let git_ref = GitCloneRef::new(format!("refs/heads/{DEFAULT_WORKSPACE_BRANCH}"))
        .expect("default workspace branch must be a valid branch ref");
    let request = VmGitCloneRequest::new(command.repo().clone(), Some(git_ref));
    let bundle = fetch_git_clone_bundle(config, &request).await?;
    init_workspace_from_bundle_with_git(
        command.git_program(),
        command.repo(),
        command.destination(),
        &bundle,
    )?;
    warm_workspace(command)?;
    require_clean_workspace(command.git_program(), command.destination())?;
    Ok(command.destination().to_path_buf())
}

async fn fetch_git_clone_bundle(
    config: &VmClientConfig,
    request: &VmGitCloneRequest,
) -> Result<Vec<u8>, VmClientError> {
    let response = reqwest::Client::new()
        .post(config.endpoint(VM_GIT_CLONE_PATH))
        .bearer_auth(config.bearer_token().as_str())
        .json(request)
        .send()
        .await?;
    let response = require_success(response).await?;
    require_content_type(&response, GIT_BUNDLE_CONTENT_TYPE)?;
    read_bounded_bundle_body(response, config.max_bundle_bytes()).await
}

fn agent_run_stream_upload(
    summary: &AgentRunStreamSummary,
) -> Result<AgentRunStreamUpload, VmClientError> {
    let retained = fs::read(&summary.path).map_err(|source| VmClientError::Io {
        operation: "read agent run stream",
        path: summary.path.clone(),
        source,
    })?;
    Ok(AgentRunStreamUpload {
        byte_len: summary.byte_len,
        sha256_hex: summary.sha256_hex.clone(),
        truncated: summary.truncated,
        retained_sha256_hex: crate::agent_run::sha256_hex(&retained),
        retained_base64: base64_standard(&retained),
    })
}

fn base64_standard(input: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(input)
}

fn clone_bundle_with_git(
    git_program: &Path,
    git_ref: Option<&GitCloneRef>,
    destination: &Path,
    bundle: &[u8],
) -> Result<(), VmClientError> {
    let cwd = std::env::current_dir().map_err(|source| VmClientError::Io {
        operation: "read current directory",
        path: PathBuf::from("."),
        source,
    })?;
    clone_bundle_with_git_from_cwd(git_program, git_ref, destination, bundle, &cwd)
}

fn clone_bundle_with_git_from_cwd(
    git_program: &Path,
    git_ref: Option<&GitCloneRef>,
    destination: &Path,
    bundle: &[u8],
    cwd: &Path,
) -> Result<(), VmClientError> {
    let temp = TempBundle::create_near(destination, bundle, cwd)?;
    match git_ref {
        Some(git_ref) => {
            checkout_ref_from_bundle(git_program, git_ref, destination, temp.path(), cwd)
        }
        None => clone_all_from_bundle(git_program, destination, temp.path(), cwd),
    }
}

fn init_workspace_from_bundle_with_git(
    git_program: &Path,
    repo: &GitCloneRepo,
    destination: &Path,
    bundle: &[u8],
) -> Result<(), VmClientError> {
    let cwd = std::env::current_dir().map_err(|source| VmClientError::Io {
        operation: "read current directory",
        path: PathBuf::from("."),
        source,
    })?;
    init_workspace_from_bundle_with_git_from_cwd(git_program, repo, destination, bundle, &cwd)
}

fn init_workspace_from_bundle_with_git_from_cwd(
    git_program: &Path,
    repo: &GitCloneRepo,
    destination: &Path,
    bundle: &[u8],
    cwd: &Path,
) -> Result<(), VmClientError> {
    reject_existing_destination(destination, cwd)?;
    create_destination_parent(destination, cwd)?;
    let temp = TempBundle::create_near(destination, bundle, cwd)?;
    run_git_command(
        git_program,
        VmGitCloneStep::Init,
        vec![
            OsString::from("init"),
            OsString::from("--"),
            destination.as_os_str().to_os_string(),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::RemoteAdd,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(canonical_github_origin_url(repo)),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::Fetch,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("fetch"),
            OsString::from("--"),
            temp.path().as_os_str().to_os_string(),
            OsString::from(format!(
                "refs/heads/{branch}:refs/remotes/origin/{branch}",
                branch = DEFAULT_WORKSPACE_BRANCH
            )),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::CheckoutBranch,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("checkout"),
            OsString::from("-B"),
            OsString::from(DEFAULT_WORKSPACE_BRANCH),
            OsString::from(format!("refs/remotes/origin/{DEFAULT_WORKSPACE_BRANCH}")),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::SetUpstream,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("branch"),
            OsString::from("--set-upstream-to"),
            OsString::from(format!("origin/{DEFAULT_WORKSPACE_BRANCH}")),
            OsString::from(DEFAULT_WORKSPACE_BRANCH),
        ],
        cwd,
    )
}

fn clone_all_from_bundle(
    git_program: &Path,
    destination: &Path,
    bundle_path: &Path,
    cwd: &Path,
) -> Result<(), VmClientError> {
    let mut args = vec![OsString::from("clone")];
    args.push(OsString::from("--"));
    args.push(bundle_path.as_os_str().to_os_string());
    args.push(destination.as_os_str().to_os_string());
    run_git_command(git_program, VmGitCloneStep::Clone, args, cwd)
}

fn checkout_ref_from_bundle(
    git_program: &Path,
    git_ref: &GitCloneRef,
    destination: &Path,
    bundle_path: &Path,
    cwd: &Path,
) -> Result<(), VmClientError> {
    reject_existing_destination(destination, cwd)?;
    run_git_command(
        git_program,
        VmGitCloneStep::Init,
        vec![
            OsString::from("init"),
            OsString::from("--"),
            destination.as_os_str().to_os_string(),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::Fetch,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("fetch"),
            OsString::from("--"),
            bundle_path.as_os_str().to_os_string(),
            OsString::from(git_ref.as_str()),
        ],
        cwd,
    )?;
    run_git_command(
        git_program,
        VmGitCloneStep::Checkout,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("checkout"),
            OsString::from("--detach"),
            OsString::from("FETCH_HEAD"),
        ],
        cwd,
    )
}

fn run_git_command(
    git_program: &Path,
    step: VmGitCloneStep,
    args: Vec<OsString>,
    cwd: &Path,
) -> Result<(), VmClientError> {
    let mut command = Command::new(git_program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove(VM_BROKER_URL_ENV)
        .env_remove(VM_BROKER_TOKEN_ENV)
        .env("GIT_TERMINAL_PROMPT", "0");
    let output = process_spawn::output(&mut command)
        .map_err(|source| VmClientError::GitSpawn { step, source })?;
    if output.status.success() {
        return Ok(());
    }
    Err(VmClientError::GitFailed {
        step,
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn run_git_command_output(
    git_program: &Path,
    step: VmGitCloneStep,
    args: Vec<OsString>,
    cwd: &Path,
) -> Result<std::process::Output, VmClientError> {
    let mut command = Command::new(git_program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove(VM_BROKER_URL_ENV)
        .env_remove(VM_BROKER_TOKEN_ENV)
        .env("GIT_TERMINAL_PROMPT", "0");
    let output = process_spawn::output(&mut command)
        .map_err(|source| VmClientError::GitSpawn { step, source })?;
    if output.status.success() {
        return Ok(output);
    }
    Err(VmClientError::GitFailed {
        step,
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

impl std::fmt::Display for VmGitCloneStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clone => f.write_str("git clone"),
            Self::Init => f.write_str("git init"),
            Self::Fetch => f.write_str("git fetch"),
            Self::Checkout => f.write_str("git checkout"),
            Self::RemoteAdd => f.write_str("git remote add"),
            Self::CheckoutBranch => f.write_str("git checkout branch"),
            Self::SetUpstream => f.write_str("git branch --set-upstream-to"),
            Self::Status => f.write_str("git status"),
        }
    }
}

impl std::fmt::Display for VmWorkspaceWarmStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FlakeMetadata => f.write_str("nix flake metadata"),
            Self::DevShell => f.write_str("nix develop"),
        }
    }
}

fn parse_broker_url(raw: &str) -> Result<Url, VmClientConfigError> {
    let mut url = Url::parse(raw).map_err(|source| VmClientConfigError::InvalidBrokerUrl {
        raw: raw.to_string(),
        parse_error: source.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(VmClientConfigError::UnsupportedBrokerUrlScheme {
            raw: raw.to_string(),
            scheme: url.scheme().to_string(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(VmClientConfigError::BrokerUrlHasQueryOrFragment(
            raw.to_string(),
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

async fn require_success(response: reqwest::Response) -> Result<reqwest::Response, VmClientError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let body = response.bytes().await?;
    let message = broker_error_message(status, &body);
    Err(VmClientError::BrokerHttp { status, message })
}

fn broker_error_message(status: u16, body: &[u8]) -> String {
    if let Ok(error) = serde_json::from_slice::<VmGitCloneErrorResponse>(body) {
        return error.message().to_string();
    }
    let message = String::from_utf8_lossy(body).trim().to_string();
    if message.is_empty() {
        format!("unexpected broker response status {status}")
    } else {
        message
    }
}

fn require_content_type(
    response: &reqwest::Response,
    expected: &'static str,
) -> Result<(), VmClientError> {
    let actual = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if actual
        .as_deref()
        .is_some_and(|content_type| content_type.split(';').next() == Some(expected))
    {
        return Ok(());
    }
    Err(VmClientError::UnexpectedContentType { actual, expected })
}

async fn read_bounded_bundle_body(
    mut response: reqwest::Response,
    max_bundle_bytes: u64,
) -> Result<Vec<u8>, VmClientError> {
    if let Some(bytes) = response.content_length()
        && bytes > max_bundle_bytes
    {
        return Err(VmClientError::BundleTooLarge {
            bytes,
            max_bundle_bytes,
        });
    }

    let mut body = Vec::new();
    let mut bytes_read = 0u64;
    while let Some(chunk) = response.chunk().await? {
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        bytes_read = bytes_read.saturating_add(chunk_len);
        if bytes_read > max_bundle_bytes {
            return Err(VmClientError::BundleTooLarge {
                bytes: bytes_read,
                max_bundle_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl TempBundle {
    fn create_near(destination: &Path, bytes: &[u8], cwd: &Path) -> Result<Self, VmClientError> {
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            cwd.join(parent)
        };
        let parent = fs::canonicalize(&parent).map_err(|source| VmClientError::Io {
            operation: "canonicalize temporary bundle parent",
            path: parent.to_path_buf(),
            source,
        })?;
        let path = parent.join(format!(".writ-vm-{}.bundle", uuid::Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|source| VmClientError::Io {
            operation: "create temporary bundle",
            path: path.clone(),
            source,
        })?;
        file.write_all(bytes).map_err(|source| VmClientError::Io {
            operation: "write temporary bundle",
            path: path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| VmClientError::Io {
            operation: "sync temporary bundle",
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn reject_existing_destination(destination: &Path, cwd: &Path) -> Result<(), VmClientError> {
    let path = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        cwd.join(destination)
    };
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(VmClientError::DestinationAlreadyExists(
            destination.to_path_buf(),
        )),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(VmClientError::Io {
            operation: "inspect checkout destination",
            path,
            source,
        }),
    }
}

fn create_destination_parent(destination: &Path, cwd: &Path) -> Result<(), VmClientError> {
    let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        cwd.join(parent)
    };
    fs::create_dir_all(&parent).map_err(|source| VmClientError::Io {
        operation: "create workspace parent directory",
        path: parent,
        source,
    })
}

fn canonical_github_origin_url(repo: &GitCloneRepo) -> String {
    let repo_ref = repo.as_repo_ref();
    format!(
        "https://github.com/{}/{}.git",
        repo_ref.owner, repo_ref.name
    )
}

fn warm_workspace(command: &VmWorkspaceInitCommand) -> Result<(), VmClientError> {
    match command.warm() {
        WorkspaceWarmMode::None => Ok(()),
        WorkspaceWarmMode::Sources => run_nix_flake_metadata(command),
        WorkspaceWarmMode::DevShell => {
            run_nix_flake_metadata(command)?;
            run_nix_develop_true(command)
        }
    }
}

fn run_nix_flake_metadata(command: &VmWorkspaceInitCommand) -> Result<(), VmClientError> {
    run_nix_command(
        command.nix_program(),
        VmWorkspaceWarmStep::FlakeMetadata,
        vec![
            OsString::from("--option"),
            OsString::from("builders"),
            OsString::from(""),
            OsString::from("--option"),
            OsString::from("max-jobs"),
            OsString::from("0"),
            OsString::from("--option"),
            OsString::from("fallback"),
            OsString::from("false"),
            OsString::from("flake"),
            OsString::from("metadata"),
            OsString::from("--refresh"),
            OsString::from("--no-write-lock-file"),
        ],
        command.destination(),
    )
}

fn run_nix_develop_true(command: &VmWorkspaceInitCommand) -> Result<(), VmClientError> {
    let mut args: Vec<OsString> = nix_develop_command_args(DEFAULT_DEVSHELL_ATTR)
        .into_iter()
        .map(OsString::from)
        .collect();
    args.push(OsString::from("true"));
    run_nix_command(
        command.nix_program(),
        VmWorkspaceWarmStep::DevShell,
        args,
        command.destination(),
    )
}

fn run_nix_command(
    nix_program: &Path,
    step: VmWorkspaceWarmStep,
    args: Vec<OsString>,
    cwd: &Path,
) -> Result<(), VmClientError> {
    let mut command = Command::new(nix_program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove(VM_BROKER_URL_ENV)
        .env_remove(VM_BROKER_TOKEN_ENV);
    let output = process_spawn::output(&mut command)
        .map_err(|source| VmClientError::NixSpawn { step, source })?;
    if output.status.success() {
        return Ok(());
    }
    Err(VmClientError::NixFailed {
        step,
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn require_clean_workspace(git_program: &Path, destination: &Path) -> Result<(), VmClientError> {
    let output = run_git_command_output(
        git_program,
        VmGitCloneStep::Status,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
        ],
        Path::new("/"),
    )?;
    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if status.is_empty() {
        Ok(())
    } else {
        Err(VmClientError::WorkspaceDirty { status })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn repo() -> GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    async fn serve_once(response: String) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_for_task = Arc::clone(&captured);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request);
                    let content_length = header
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    while request.len() < body_start + content_length {
                        let read = stream.read(&mut buf).await.unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                    }
                    break;
                }
            }
            *captured_for_task.lock().unwrap() = String::from_utf8_lossy(&request).into_owned();
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}/"), captured)
    }

    fn http_response(status: &str, content_type: &str, body: &[u8]) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
    }

    fn http_response_without_content_length(
        status: &str,
        content_type: &str,
        body: &[u8],
    ) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
            String::from_utf8_lossy(body)
        )
    }

    fn write_fake_git(dir: &Path) -> PathBuf {
        let path = dir.join("fake-git");
        let log = dir.join("git.log");
        let script = format!(
            "#!/bin/sh\n\
             set -eu\n\
             printf '%s\\n' \"$*\" >> {log}\n\
             printf 'broker_url=%s\\n' \"${{WRIT_BROKER_URL-unset}}\" >> {log}\n\
             printf 'broker_token=%s\\n' \"${{WRIT_BROKER_TOKEN-unset}}\" >> {log}\n\
             if [ \"${{1:-}}\" = 'clone' ]; then\n\
             shift\n\
             test \"${{1:-}}\" = '--'\n\
             shift\n\
             bundle=\"$1\"\n\
             dest=\"$2\"\n\
             test -f \"$bundle\"\n\
             mkdir -p \"$dest/.git\"\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = 'init' ]; then\n\
             shift\n\
             test \"${{1:-}}\" = '--'\n\
             shift\n\
             mkdir -p \"$1/.git\"\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = '-C' ]; then\n\
             dest=\"$2\"\n\
             shift 2\n\
             if [ \"${{1:-}}\" = 'remote' ]; then\n\
             test \"${{2:-}}\" = 'add'\n\
             test \"${{3:-}}\" = 'origin'\n\
             test -n \"${{4:-}}\"\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = 'fetch' ]; then\n\
             shift\n\
             test \"${{1:-}}\" = '--'\n\
             shift\n\
             test -f \"$1\"\n\
             test -n \"$2\"\n\
             printf 'fetched=%s\\n' \"$2\" > \"$dest/FETCH_HEAD\"\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = 'checkout' ]; then\n\
             if [ \"${{2:-}}\" = '-B' ]; then\n\
             test \"${{3:-}}\" = 'main'\n\
             test \"${{4:-}}\" = 'refs/remotes/origin/main'\n\
             exit 0\n\
             fi\n\
             test \"${{2:-}}\" = '--detach'\n\
             test \"${{3:-}}\" = 'FETCH_HEAD'\n\
             test -f \"$dest/FETCH_HEAD\"\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = 'branch' ]; then\n\
             test \"${{2:-}}\" = '--set-upstream-to'\n\
             test \"${{3:-}}\" = 'origin/main'\n\
             test \"${{4:-}}\" = 'main'\n\
             exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = 'status' ]; then\n\
             test \"${{2:-}}\" = '--porcelain=v1'\n\
             exit 0\n\
             fi\n\
             fi\n\
             exit 64\n",
            log = shell_quote(&log),
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn leaked_bundle_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".writ-vm-"))
            .count()
    }

    fn required_test_tool(name: &str) -> PathBuf {
        let path = std::env::var_os("PATH")
            .unwrap_or_else(|| panic!("PATH must contain {name} for vm_client tests"));
        for dir in std::env::split_paths(&path) {
            let candidate = if dir.is_absolute() {
                dir.join(name)
            } else {
                std::env::current_dir().unwrap().join(dir).join(name)
            };
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("{name} not found on PATH for vm_client tests");
    }

    fn run_test_git(git: &Path, args: &[&str]) {
        let output = Command::new(git)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn get_session_json_gets_session_endpoint_with_bearer_token() {
        let body = br#"{"api":"writ-vm-http","version":1,"session_id":"test-session"}"#;
        let (broker_url, captured) =
            serve_once(http_response("200 OK", "application/json", body)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let session = get_session_json(&config).await.unwrap();

        assert_eq!(session["api"], "writ-vm-http");
        assert_eq!(session["version"], 1);
        assert_eq!(session["session_id"], "test-session");
        let request = captured.lock().unwrap().clone();
        assert!(request.starts_with("GET /v1/session HTTP/1.1"), "{request}");
        assert!(
            request.contains("authorization: Bearer writ-vm-secret")
                || request.contains("Authorization: Bearer writ-vm-secret"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn plain_text_broker_errors_are_preserved() {
        let (broker_url, _captured) = serve_once(http_response(
            "405 Method Not Allowed",
            "text/plain",
            b"method not allowed",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let err = get_session_json(&config).await.unwrap_err();

        assert!(matches!(
            err,
            VmClientError::BrokerHttp {
                status: 405,
                message
            } if message == "method not allowed"
        ));
    }

    #[tokio::test]
    async fn fetch_agent_run_config_gets_one_run_config_with_bearer_token() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000501".parse().unwrap();
        let prompt = AgentPrompt::new("SECRET prompt");
        let body = serde_json::to_vec(&VmAgentRunConfigResponse::new(
            run_id,
            prompt.clone(),
            "gpt-5.4-mini",
        ))
        .unwrap();
        let (broker_url, captured) =
            serve_once(http_response("200 OK", "application/json", &body)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let (fetched_prompt, fetched_model) =
            fetch_agent_run_config(&config, run_id).await.unwrap();

        assert_eq!(fetched_prompt, prompt);
        assert_eq!(fetched_model, "gpt-5.4-mini");
        let request = captured.lock().unwrap().clone();
        assert!(
            request.starts_with(
                "GET /v1/agent-runs/00000000-0000-0000-0000-000000000501/config HTTP/1.1"
            ),
            "{request}"
        );
        assert!(
            request.contains("authorization: Bearer writ-vm-secret")
                || request.contains("Authorization: Bearer writ-vm-secret"),
            "{request}"
        );
        assert!(!format!("{fetched_prompt:?}").contains(prompt.as_str()));
    }

    #[tokio::test]
    async fn upload_agent_run_outcome_posts_stream_metadata_and_retained_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000502".parse().unwrap();
        let stdout_path = dir.path().join("stdout.log");
        let stderr_path = dir.path().join("stderr.log");
        fs::write(&stdout_path, b"Hello from Claude\n").unwrap();
        fs::write(&stderr_path, b"").unwrap();
        let outcome = AgentRunOutcome {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamSummary {
                path: stdout_path,
                byte_len: 18,
                sha256_hex: crate::agent_run::sha256_hex(b"Hello from Claude\n"),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: stderr_path,
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
            },
        };
        let (broker_url, captured) = serve_once(http_response("200 OK", "text/plain", b"ok")).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        upload_agent_run_outcome(&config, &outcome).await.unwrap();

        let request = captured.lock().unwrap().clone();
        assert!(
            request.starts_with(
                "POST /v1/agent-runs/00000000-0000-0000-0000-000000000502/outcome HTTP/1.1"
            ),
            "{request}"
        );
        assert!(
            request.contains("authorization: Bearer writ-vm-secret")
                || request.contains("Authorization: Bearer writ-vm-secret"),
            "{request}"
        );
        assert!(request.contains(r#""exit_code":0"#), "{request}");
        assert!(
            request.contains(r#""retained_base64":"SGVsbG8gZnJvbSBDbGF1ZGUK""#),
            "{request}"
        );
        assert!(!request.contains("Hello from Claude"), "{request}");
    }

    #[tokio::test]
    async fn clone_from_broker_posts_request_and_clones_returned_bundle_without_token_in_git_argv()
    {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let bundle = b"bundle bytes";
        let (broker_url, captured) = serve_once(http_response(
            "200 OK",
            "application/x-git-bundle; charset=utf-8",
            bundle,
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let destination = dir.path().join("checkout");
        let command = VmGitCloneCommand::new(
            repo(),
            Some("refs/heads/main".parse().unwrap()),
            Some(destination.clone()),
            git,
        )
        .unwrap();

        let cloned = clone_from_broker(&config, &command).await.unwrap();

        assert_eq!(cloned, destination);
        assert!(destination.join(".git").is_dir());
        let request = captured.lock().unwrap().clone();
        assert!(
            request.starts_with("POST /v1/git/clone HTTP/1.1"),
            "{request}"
        );
        assert!(
            request.contains("authorization: Bearer writ-vm-secret")
                || request.contains("Authorization: Bearer writ-vm-secret"),
            "{request}"
        );
        assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
        assert!(request.contains(r#""ref":"refs/heads/main""#), "{request}");

        let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
        assert!(git_log.contains("init -- "), "{git_log}");
        assert!(
            git_log.contains("fetch -- ") && git_log.contains(" refs/heads/main"),
            "{git_log}"
        );
        assert!(
            git_log.contains("checkout --detach FETCH_HEAD"),
            "{git_log}"
        );
        assert!(!git_log.contains("--branch"), "{git_log}");
        assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
        assert!(git_log.contains("broker_url=unset"), "{git_log}");
        assert!(git_log.contains("broker_token=unset"), "{git_log}");
        assert_eq!(leaked_bundle_count(dir.path()), 0);
    }

    #[tokio::test]
    async fn clone_from_broker_rejects_bundle_larger_than_client_limit_before_running_git() {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let bundle = b"bundle bytes";
        let (broker_url, _captured) =
            serve_once(http_response("200 OK", "application/x-git-bundle", bundle)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret")
            .unwrap()
            .with_max_bundle_bytes(4)
            .unwrap();
        let command =
            VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

        let err = clone_from_broker(&config, &command).await.unwrap_err();

        assert!(matches!(
            err,
            VmClientError::BundleTooLarge {
                bytes,
                max_bundle_bytes: 4,
            } if bytes == u64::try_from(bundle.len()).unwrap()
        ));
        assert!(!dir.path().join("git.log").exists());
        assert_eq!(leaked_bundle_count(dir.path()), 0);
    }

    #[tokio::test]
    async fn clone_from_broker_counts_streamed_bundle_bytes_when_length_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let bundle = b"bundle bytes";
        let (broker_url, _captured) = serve_once(http_response_without_content_length(
            "200 OK",
            "application/x-git-bundle",
            bundle,
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret")
            .unwrap()
            .with_max_bundle_bytes(4)
            .unwrap();
        let command =
            VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

        let err = clone_from_broker(&config, &command).await.unwrap_err();

        assert!(matches!(
            err,
            VmClientError::BundleTooLarge {
                bytes,
                max_bundle_bytes: 4,
            } if bytes == u64::try_from(bundle.len()).unwrap()
        ));
        assert!(!dir.path().join("git.log").exists());
        assert_eq!(leaked_bundle_count(dir.path()), 0);
    }

    #[test]
    fn clone_bundle_with_real_git_supports_full_head_refs_from_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let git = required_test_tool("git");
        let source = dir.path().join("source");
        let bundle = dir.path().join("main.bundle");
        let checkout_parent = tempfile::tempdir().unwrap();
        let relative_checkout = PathBuf::from("checkout");

        let source_arg = source.to_str().unwrap();
        run_test_git(&git, &["init", "--", source_arg]);
        run_test_git(
            &git,
            &["-C", source_arg, "config", "user.email", "a@example.com"],
        );
        run_test_git(&git, &["-C", source_arg, "config", "user.name", "a"]);
        run_test_git(
            &git,
            &["-C", source_arg, "config", "commit.gpgsign", "false"],
        );
        fs::write(source.join("file.txt"), "hello\n").unwrap();
        run_test_git(&git, &["-C", source_arg, "add", "file.txt"]);
        run_test_git(&git, &["-C", source_arg, "commit", "-m", "init"]);
        run_test_git(&git, &["-C", source_arg, "branch", "-M", "main"]);
        run_test_git(
            &git,
            &[
                "-C",
                source_arg,
                "bundle",
                "create",
                bundle.to_str().unwrap(),
                "refs/heads/main",
            ],
        );

        clone_bundle_with_git_from_cwd(
            &git,
            Some(&"refs/heads/main".parse().unwrap()),
            &relative_checkout,
            &fs::read(&bundle).unwrap(),
            checkout_parent.path(),
        )
        .unwrap();
        let checkout = checkout_parent.path().join(&relative_checkout);

        assert_eq!(
            fs::read_to_string(checkout.join("file.txt")).unwrap(),
            "hello\n"
        );
        let head = Command::new(&git)
            .args([
                "-C",
                checkout.to_str().unwrap(),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .output()
            .unwrap();
        assert!(head.status.success());
        assert_eq!(String::from_utf8_lossy(&head.stdout).trim(), "HEAD");
    }

    #[test]
    fn workspace_init_creates_clean_main_branch_tracking_origin_from_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let git = required_test_tool("git");
        let source = dir.path().join("source");
        let bundle = dir.path().join("main.bundle");
        let checkout = dir.path().join("checkout");

        let source_arg = source.to_str().unwrap();
        run_test_git(&git, &["init", "--", source_arg]);
        run_test_git(
            &git,
            &["-C", source_arg, "config", "user.email", "a@example.com"],
        );
        run_test_git(&git, &["-C", source_arg, "config", "user.name", "a"]);
        run_test_git(
            &git,
            &["-C", source_arg, "config", "commit.gpgsign", "false"],
        );
        fs::write(source.join("file.txt"), "hello\n").unwrap();
        run_test_git(&git, &["-C", source_arg, "add", "file.txt"]);
        run_test_git(&git, &["-C", source_arg, "commit", "-m", "init"]);
        run_test_git(&git, &["-C", source_arg, "branch", "-M", "main"]);
        run_test_git(
            &git,
            &[
                "-C",
                source_arg,
                "bundle",
                "create",
                bundle.to_str().unwrap(),
                "refs/heads/main",
            ],
        );

        init_workspace_from_bundle_with_git_from_cwd(
            &git,
            &repo(),
            &checkout,
            &fs::read(&bundle).unwrap(),
            dir.path(),
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(checkout.join("file.txt")).unwrap(),
            "hello\n"
        );
        let branch = Command::new(&git)
            .args([
                "-C",
                checkout.to_str().unwrap(),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .output()
            .unwrap();
        assert!(branch.status.success());
        assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
        let upstream = Command::new(&git)
            .args([
                "-C",
                checkout.to_str().unwrap(),
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{u}",
            ])
            .output()
            .unwrap();
        assert!(upstream.status.success());
        assert_eq!(
            String::from_utf8_lossy(&upstream.stdout).trim(),
            "origin/main"
        );
        let status = Command::new(&git)
            .args(["-C", checkout.to_str().unwrap(), "status", "--porcelain=v1"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert_eq!(String::from_utf8_lossy(&status.stdout).trim(), "");
    }

    #[tokio::test]
    async fn workspace_init_from_broker_posts_main_ref_and_does_not_leak_token_to_git() {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let (broker_url, captured) = serve_once(http_response(
            "200 OK",
            "application/x-git-bundle",
            b"bundle bytes",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let checkout = dir.path().join("checkout");
        let command = VmWorkspaceInitCommand::new(
            repo(),
            Some(checkout.clone()),
            WorkspaceWarmMode::None,
            git,
            "nix",
        )
        .unwrap();

        let initialized = init_workspace_from_broker(&config, &command).await.unwrap();

        assert_eq!(initialized, checkout);
        let request = captured.lock().unwrap().clone();
        assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
        assert!(request.contains(r#""ref":"refs/heads/main""#), "{request}");
        let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
        assert!(
            git_log.contains("fetch -- ")
                && git_log.contains("refs/heads/main:refs/remotes/origin/main"),
            "{git_log}"
        );
        assert!(
            git_log.contains("remote add origin https://github.com/owner/repo.git"),
            "{git_log}"
        );
        assert!(
            git_log.contains("checkout -B main refs/remotes/origin/main"),
            "{git_log}"
        );
        assert!(
            git_log.contains("branch --set-upstream-to origin/main main"),
            "{git_log}"
        );
        assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
        assert!(git_log.contains("broker_url=unset"), "{git_log}");
        assert!(git_log.contains("broker_token=unset"), "{git_log}");
    }

    #[tokio::test]
    async fn clone_from_broker_ref_path_rejects_existing_destination_before_git_init() {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let destination = dir.path().join("checkout");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep.txt"), "do not overwrite\n").unwrap();
        let (broker_url, _captured) = serve_once(http_response(
            "200 OK",
            "application/x-git-bundle",
            b"bundle bytes",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitCloneCommand::new(
            repo(),
            Some("refs/heads/main".parse().unwrap()),
            Some(destination.clone()),
            git,
        )
        .unwrap();

        let err = clone_from_broker(&config, &command).await.unwrap_err();

        assert!(
            matches!(err, VmClientError::DestinationAlreadyExists(path) if path == destination)
        );
        assert_eq!(
            fs::read_to_string(destination.join("keep.txt")).unwrap(),
            "do not overwrite\n"
        );
        assert!(!dir.path().join("git.log").exists());
        assert_eq!(leaked_bundle_count(dir.path()), 0);
    }

    #[tokio::test]
    async fn clone_from_broker_does_not_run_git_when_broker_denies_request() {
        let dir = tempfile::tempdir().unwrap();
        let git = write_fake_git(dir.path());
        let body = br#"{"error":"denied","message":"not allowed"}"#;
        let (broker_url, _captured) =
            serve_once(http_response("403 Forbidden", "application/json", body)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command =
            VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

        let err = clone_from_broker(&config, &command).await.unwrap_err();

        assert!(matches!(
            err,
            VmClientError::BrokerHttp {
                status: 403,
                message
            } if message == "not allowed"
        ));
        assert!(!dir.path().join("git.log").exists());
        assert_eq!(leaked_bundle_count(dir.path()), 0);
    }

    #[test]
    fn clone_command_defaults_destination_to_repo_name() {
        let command = VmGitCloneCommand::new(repo(), None, None, "git").unwrap();
        assert_eq!(command.destination(), Path::new("repo"));
    }

    #[test]
    fn client_config_debug_redacts_broker_token() {
        let config = VmClientConfig::new("http://192.168.252.1:18080", "writ-vm-secret").unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("writ-vm-secret"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn broker_token_rejects_header_unsafe_values() {
        assert!(matches!(
            VmClientConfig::new("http://192.168.252.1:18080", "has space"),
            Err(VmClientConfigError::InvalidToken)
        ));
        assert!(matches!(
            VmClientConfig::new("http://192.168.252.1:18080", "has\nnewline"),
            Err(VmClientConfigError::InvalidToken)
        ));
        for token in ["has+plus", "has/slash", "has=equals", "has:colon", "has@at"] {
            assert!(
                matches!(
                    VmClientConfig::new("http://192.168.252.1:18080", token),
                    Err(VmClientConfigError::InvalidToken)
                ),
                "accepted {token:?}"
            );
        }
    }

    fn valid_owner() -> impl Strategy<Value = String> {
        prop_oneof!["[A-Za-z0-9]", "[A-Za-z0-9][A-Za-z0-9-]{0,37}[A-Za-z0-9]",]
    }

    fn valid_repo_name() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}".prop_filter("not dot-only or .git-suffixed", |name| {
            !matches!(name.as_str(), "." | "..") && !name.ends_with(".git")
        })
    }

    proptest! {
        #[test]
        fn clone_command_default_destination_is_repo_name(owner in valid_owner(), name in valid_repo_name()) {
            let repo: GitCloneRepo = format!("{owner}/{name}").parse().unwrap();

            let command = VmGitCloneCommand::new(repo, None, None, "git").unwrap();

            prop_assert_eq!(command.destination(), Path::new(&name));
        }

        #[test]
        fn broker_token_debug_never_contains_secret(hex in "[A-F0-9]{16,64}") {
            let token = format!("secret_{hex}");
            let config = VmClientConfig::new("http://192.168.252.1:18080", token.clone()).unwrap();

            let debug = format!("{config:?}");

            prop_assert!(!debug.contains(&token), "{debug}");
            prop_assert!(debug.contains("<redacted>"), "{debug}");
        }
    }
}
