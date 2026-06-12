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
    DEFAULT_DEVSHELL_ATTR, DEFAULT_WORKSPACE_BRANCH, GIT_BUNDLE_CONTENT_TYPE,
    GIT_PUSH_BUNDLE_CONTENT_TYPE, GitBranchName, GitCloneRef, GitCloneRepo, GitObjectId,
    VM_FLAKE_PROVISION_PATH, VM_GIT_CLONE_PATH, VM_GIT_PUSH_PATH, VmFlakeProvisionErrorResponse,
    VmFlakeProvisionRequest, VmFlakeProvisionResponse, VmGitCloneErrorResponse, VmGitCloneRequest,
    VmGitPushErrorResponse, VmGitPushMetadata, VmGitPushRequest, VmGitPushStagedReceipt,
    WorkspaceWarmMode, default_workspace_destination, encode_vm_git_push_request_body,
    nix_develop_command_args, nix_substituters_override_args,
};

pub const VM_BROKER_URL_ENV: &str = "WRIT_BROKER_URL";
pub const VM_BROKER_TOKEN_ENV: &str = "WRIT_BROKER_TOKEN";
/// The strict, pre-warm-only substituter URL, injected by the daemon exactly
/// when the broker serves a pre-warm cache dir. When present, the devShell
/// warm's nix invocations replace their substituters with this URL, so the
/// warm never reaches the upstream-proxying cache view.
pub const VM_NIX_PREWARM_URL_ENV: &str = "WRIT_NIX_PREWARM_URL";
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
pub struct VmGitPushCommand {
    repo: GitCloneRepo,
    branch: GitBranchName,
    new_head: GitObjectId,
    expected_remote_head: Option<GitObjectId>,
    workdir: PathBuf,
    git_program: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmWorkspaceInitCommand {
    repo: GitCloneRepo,
    destination: PathBuf,
    warm: WorkspaceWarmMode,
    git_program: PathBuf,
    nix_program: PathBuf,
    /// The strict pre-warm-only substituter (see [`VM_NIX_PREWARM_URL_ENV`]).
    /// `Some` pins the devShell warm's nix invocations to this URL; `None` (no
    /// pre-warming in this deployment) leaves them on the session default.
    prewarm_substituter_url: Option<String>,
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
    ResolveHead,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmGitPushStep {
    RevParse,
    BundleCreate,
    BundleListHeads,
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

#[derive(Debug, thiserror::Error)]
pub enum VmGitPushCommandError {
    #[error("workdir path must not be empty")]
    EmptyWorkdir,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmWorkspaceInitCommandError {
    #[error("workspace destination path must not be empty")]
    EmptyDestination,
    #[error("pre-warm substituter URL must be http or https: {0:?}")]
    UnsupportedPrewarmSubstituterUrl(String),
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
    #[error("{step} git command could not be spawned: {source}")]
    GitPushSpawn {
        step: VmGitPushStep,
        source: std::io::Error,
    },
    #[error("{step} git command failed with status {status}: {stderr}")]
    GitPushFailed {
        step: VmGitPushStep,
        status: ExitStatus,
        stderr: String,
    },
    #[error("local branch {branch} resolves to {actual} but the push asserts new_head {expected}")]
    BranchHeadMismatch {
        branch: String,
        expected: String,
        actual: String,
    },
    #[error("git bundle create produced an empty bundle for branch {branch}")]
    BundleEmpty { branch: String },
    #[error(
        "git bundle for branch {branch} advertises {actual} for {ref_name} but the push asserts new_head {expected}; the branch may have moved during push preparation"
    )]
    BundleHeadMismatch {
        branch: String,
        ref_name: String,
        expected: String,
        actual: String,
    },
    #[error("git bundle for branch {branch} did not advertise {ref_name} in its ref list")]
    BundleMissingBranch { branch: String, ref_name: String },
    #[error("VM broker returned a malformed Git push receipt: {0}")]
    BrokerInvalidReceipt(String),
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

impl VmGitPushCommand {
    pub fn new(
        repo: GitCloneRepo,
        branch: GitBranchName,
        new_head: GitObjectId,
        expected_remote_head: Option<GitObjectId>,
        workdir: impl Into<PathBuf>,
        git_program: impl Into<PathBuf>,
    ) -> Result<Self, VmGitPushCommandError> {
        let workdir = workdir.into();
        if workdir.as_os_str().is_empty() {
            return Err(VmGitPushCommandError::EmptyWorkdir);
        }
        Ok(Self {
            repo,
            branch,
            new_head,
            expected_remote_head,
            workdir,
            git_program: git_program.into(),
        })
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn branch(&self) -> &GitBranchName {
        &self.branch
    }

    pub fn new_head(&self) -> &GitObjectId {
        &self.new_head
    }

    pub fn expected_remote_head(&self) -> Option<&GitObjectId> {
        self.expected_remote_head.as_ref()
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
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
        prewarm_substituter_url: Option<String>,
    ) -> Result<Self, VmWorkspaceInitCommandError> {
        let destination = match destination {
            Some(path) => path,
            None => default_workspace_destination(&repo),
        };
        if destination.as_os_str().is_empty() {
            return Err(VmWorkspaceInitCommandError::EmptyDestination);
        }
        if let Some(url) = &prewarm_substituter_url
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            return Err(VmWorkspaceInitCommandError::UnsupportedPrewarmSubstituterUrl(url.clone()));
        }
        Ok(Self {
            repo,
            destination,
            warm,
            git_program: git_program.into(),
            nix_program: nix_program.into(),
            prewarm_substituter_url,
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

    pub fn prewarm_substituter_url(&self) -> Option<&str> {
        self.prewarm_substituter_url.as_deref()
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

pub async fn push_to_broker(
    config: &VmClientConfig,
    command: &VmGitPushCommand,
) -> Result<VmGitPushStagedReceipt, VmClientError> {
    let bundle = produce_push_bundle(
        command.git_program(),
        command.branch(),
        command.new_head(),
        command.expected_remote_head(),
        command.workdir(),
        config.max_bundle_bytes(),
    )?;
    let metadata = VmGitPushMetadata::new(
        command.repo().clone(),
        command.branch().clone(),
        command.expected_remote_head().cloned(),
        command.new_head().clone(),
    );
    let request = VmGitPushRequest::new(metadata, bundle).map_err(|err| match err {
        crate::vm_git::VmGitPushRequestError::EmptyBundle => VmClientError::BundleEmpty {
            branch: command.branch().as_str().to_string(),
        },
    })?;
    let body = encode_vm_git_push_request_body(&request)
        .expect("encoded VmGitPushMetadata is always valid JSON");
    let response = reqwest::Client::new()
        .post(config.endpoint(VM_GIT_PUSH_PATH))
        .bearer_auth(config.bearer_token().as_str())
        .header(reqwest::header::CONTENT_TYPE, GIT_PUSH_BUNDLE_CONTENT_TYPE)
        .body(body)
        .send()
        .await?;
    let response = require_success(response).await?;
    let body = response.bytes().await?;
    serde_json::from_slice::<VmGitPushStagedReceipt>(&body)
        .map_err(|err| VmClientError::BrokerInvalidReceipt(err.to_string()))
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
    // Ask the broker to provision the flake's locked inputs into the shared
    // cache *before* warm, so the no-egress guest's `nix develop` can evaluate
    // the locked flake without reaching github. Best-effort: warm runs whatever
    // the outcome, and surfaces its own error if the inputs really were needed.
    provision_flake_inputs_best_effort(config, command).await;
    warm_workspace(command)?;
    require_clean_workspace(command.git_program(), command.destination())?;
    Ok(command.destination().to_path_buf())
}

/// Reasons a provision attempt did not complete that the guest treats as
/// non-fatal: provisioning is an optimisation, so each is logged and swallowed.
#[derive(Debug)]
enum FlakeProvisionDegrade {
    /// The provision request never reached the broker (transport failure).
    Request(reqwest::Error),
    /// The broker answered with a non-success status (e.g. `404` when the
    /// endpoint is disabled, `403` when unauthorized, `5xx` on a host failure).
    Status { code: u16, message: Option<String> },
    /// The broker answered `2xx` but the body was not a provision response.
    Body(reqwest::Error),
}

impl std::fmt::Display for FlakeProvisionDegrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(err) => write!(f, "broker request failed: {err}"),
            Self::Status {
                code,
                message: Some(message),
            } => write!(f, "broker returned status {code}: {message}"),
            Self::Status {
                code,
                message: None,
            } => write!(f, "broker returned status {code}"),
            Self::Body(err) => write!(f, "broker response was not understood: {err}"),
        }
    }
}

/// Best-effort flake-input provisioning. Resolves the checked-out commit and
/// asks the broker to provision that `(repo, rev)`'s locked inputs. Any failure
/// — unresolved HEAD, transport, refusal, cache miss — is reported on stderr
/// and swallowed; the caller proceeds to warm regardless. Skipped entirely when
/// no warm step will run, since nothing in the workspace would consume the
/// inputs yet.
async fn provision_flake_inputs_best_effort(
    config: &VmClientConfig,
    command: &VmWorkspaceInitCommand,
) {
    if command.warm() == WorkspaceWarmMode::None {
        return;
    }
    let rev = match resolve_head_object_id(command.git_program(), command.destination()) {
        Ok(rev) => rev,
        Err(message) => {
            eprintln!("writ-vm: skipping flake-input provisioning: {message}");
            return;
        }
    };
    let request = VmFlakeProvisionRequest::new(command.repo().clone(), rev);
    match post_flake_provision(config, &request).await {
        Ok(VmFlakeProvisionResponse::Provisioned {
            input_count,
            archived_path_count,
            ..
        }) => eprintln!(
            "writ-vm: provisioned {input_count} flake input(s) into the broker cache \
             ({archived_path_count} store path(s))"
        ),
        Ok(VmFlakeProvisionResponse::MirrorNotCached) => eprintln!(
            "writ-vm: flake inputs were not pre-provisioned (broker has no cached mirror); \
             an offline `nix develop` may fail to fetch them"
        ),
        Err(degrade) => {
            eprintln!("writ-vm: flake-input provisioning unavailable: {degrade}")
        }
    }
}

/// Resolve the commit currently checked out at `destination`. Returns a
/// human-readable message (not a hard error) so the best-effort caller can log
/// and continue.
fn resolve_head_object_id(git_program: &Path, destination: &Path) -> Result<GitObjectId, String> {
    let cwd = std::env::current_dir()
        .map_err(|source| format!("cannot read current directory: {source}"))?;
    let output = run_git_command_output(
        git_program,
        VmGitCloneStep::ResolveHead,
        vec![
            OsString::from("-C"),
            destination.as_os_str().to_os_string(),
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("--end-of-options"),
            OsString::from("HEAD^{commit}"),
        ],
        &cwd,
    )
    .map_err(|err| err.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout);
    GitObjectId::new(text.trim())
        .map_err(|err| format!("git rev-parse HEAD returned an invalid commit id: {err}"))
}

/// POST a provision request and classify the answer. Returns the broker's
/// successful outcome (provisioned or mirror-not-cached), or a
/// [`FlakeProvisionDegrade`] the caller logs and ignores.
async fn post_flake_provision(
    config: &VmClientConfig,
    request: &VmFlakeProvisionRequest,
) -> Result<VmFlakeProvisionResponse, FlakeProvisionDegrade> {
    let response = reqwest::Client::new()
        .post(config.endpoint(VM_FLAKE_PROVISION_PATH))
        .bearer_auth(config.bearer_token().as_str())
        .json(request)
        .send()
        .await
        .map_err(FlakeProvisionDegrade::Request)?;
    let status = response.status();
    if status.is_success() {
        return response
            .json::<VmFlakeProvisionResponse>()
            .await
            .map_err(FlakeProvisionDegrade::Body);
    }
    // A refusal carries a structured error body on the broker's own routes, but
    // a disabled endpoint answers `404` with plain text; tolerate both.
    let message = response
        .json::<VmFlakeProvisionErrorResponse>()
        .await
        .ok()
        .map(|err| err.message().to_string());
    Err(FlakeProvisionDegrade::Status {
        code: status.as_u16(),
        message,
    })
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

fn produce_push_bundle(
    git_program: &Path,
    branch: &GitBranchName,
    new_head: &GitObjectId,
    expected_remote_head: Option<&GitObjectId>,
    workdir: &Path,
    max_bundle_bytes: u64,
) -> Result<Vec<u8>, VmClientError> {
    verify_local_branch_head(git_program, branch, new_head, workdir)?;
    let bundle_path = TempBundlePath::reserve()?;
    create_branch_bundle(
        git_program,
        branch,
        expected_remote_head,
        workdir,
        bundle_path.path(),
    )?;
    let metadata = fs::metadata(bundle_path.path()).map_err(|source| VmClientError::Io {
        operation: "stat git push bundle",
        path: bundle_path.path().to_path_buf(),
        source,
    })?;
    if metadata.len() > max_bundle_bytes {
        return Err(VmClientError::BundleTooLarge {
            bytes: metadata.len(),
            max_bundle_bytes,
        });
    }
    let bytes = fs::read(bundle_path.path()).map_err(|source| VmClientError::Io {
        operation: "read git push bundle",
        path: bundle_path.path().to_path_buf(),
        source,
    })?;
    if bytes.is_empty() {
        return Err(VmClientError::BundleEmpty {
            branch: branch.as_str().to_string(),
        });
    }
    verify_bundle_advertises_new_head(git_program, branch, new_head, bundle_path.path())?;
    Ok(bytes)
}

fn verify_local_branch_head(
    git_program: &Path,
    branch: &GitBranchName,
    new_head: &GitObjectId,
    workdir: &Path,
) -> Result<(), VmClientError> {
    let output = run_git_push_command_output(
        git_program,
        VmGitPushStep::RevParse,
        vec![
            OsString::from("-C"),
            workdir.as_os_str().to_os_string(),
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(format!("{}^{{commit}}", branch.as_heads_ref())),
        ],
    )?;
    let actual = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    if actual == new_head.as_str() {
        return Ok(());
    }
    Err(VmClientError::BranchHeadMismatch {
        branch: branch.as_str().to_string(),
        expected: new_head.as_str().to_string(),
        actual,
    })
}

fn create_branch_bundle(
    git_program: &Path,
    branch: &GitBranchName,
    expected_remote_head: Option<&GitObjectId>,
    workdir: &Path,
    bundle_path: &Path,
) -> Result<(), VmClientError> {
    let mut args = vec![
        OsString::from("-C"),
        workdir.as_os_str().to_os_string(),
        OsString::from("bundle"),
        OsString::from("create"),
        OsString::from(bundle_path),
        OsString::from(branch.as_heads_ref()),
    ];
    if let Some(expected) = expected_remote_head {
        args.push(OsString::from("--not"));
        args.push(OsString::from(expected.as_str()));
    }
    run_git_push_command(git_program, VmGitPushStep::BundleCreate, args)
}

/// Verifies that the bundle just produced advertises `new_head` for the
/// asserted branch. This closes the TOCTOU window between
/// [`verify_local_branch_head`] and [`create_branch_bundle`]: if the local
/// branch moves between the two, `git bundle create` would package a different
/// tip than the metadata claims, and the broker would stage a receipt that
/// disagrees with the bundle.
fn verify_bundle_advertises_new_head(
    git_program: &Path,
    branch: &GitBranchName,
    new_head: &GitObjectId,
    bundle_path: &Path,
) -> Result<(), VmClientError> {
    let output = run_git_push_command_output(
        git_program,
        VmGitPushStep::BundleListHeads,
        vec![
            OsString::from("bundle"),
            OsString::from("list-heads"),
            OsString::from(bundle_path),
        ],
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_ref = branch.as_heads_ref();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((oid, ref_name)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let ref_name = ref_name.trim();
        if ref_name != expected_ref {
            continue;
        }
        let oid = oid.trim().to_ascii_lowercase();
        if oid == new_head.as_str() {
            return Ok(());
        }
        return Err(VmClientError::BundleHeadMismatch {
            branch: branch.as_str().to_string(),
            ref_name: expected_ref,
            expected: new_head.as_str().to_string(),
            actual: oid,
        });
    }
    Err(VmClientError::BundleMissingBranch {
        branch: branch.as_str().to_string(),
        ref_name: expected_ref,
    })
}

fn run_git_push_command(
    git_program: &Path,
    step: VmGitPushStep,
    args: Vec<OsString>,
) -> Result<(), VmClientError> {
    let mut command = Command::new(git_program);
    configure_push_git_env(&mut command);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = process_spawn::output(&mut command)
        .map_err(|source| VmClientError::GitPushSpawn { step, source })?;
    if output.status.success() {
        return Ok(());
    }
    Err(VmClientError::GitPushFailed {
        step,
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn run_git_push_command_output(
    git_program: &Path,
    step: VmGitPushStep,
    args: Vec<OsString>,
) -> Result<std::process::Output, VmClientError> {
    let mut command = Command::new(git_program);
    configure_push_git_env(&mut command);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = process_spawn::output(&mut command)
        .map_err(|source| VmClientError::GitPushSpawn { step, source })?;
    if output.status.success() {
        return Ok(output);
    }
    Err(VmClientError::GitPushFailed {
        step,
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Repository-selecting Git environment variables that override `-C <workdir>`.
/// If we inherit any of these from a wrapper or hook, Git would silently
/// rev-parse and bundle a different repository than the explicit workdir, so
/// we strip them before every push-related Git invocation.
const GIT_REPO_SELECTION_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

fn configure_push_git_env(command: &mut Command) {
    command
        .env_remove(VM_BROKER_URL_ENV)
        .env_remove(VM_BROKER_TOKEN_ENV)
        .env("GIT_TERMINAL_PROMPT", "0");
    for var in GIT_REPO_SELECTION_ENV {
        command.env_remove(var);
    }
}

/// Resolves `temp_root` to an absolute path. `std::env::temp_dir()` honours
/// `TMPDIR`, which is permitted to be a relative path; if we then handed that
/// to `git -C <workdir> bundle create <path>`, git would resolve it against
/// `<workdir>` rather than this process's cwd, so the bundle would be written
/// somewhere we don't expect (or fail with `ENOENT`).
fn absolutize_temp_root(temp_root: PathBuf) -> Result<PathBuf, VmClientError> {
    if temp_root.is_absolute() {
        return Ok(temp_root);
    }
    let cwd = std::env::current_dir().map_err(|source| VmClientError::Io {
        operation: "resolve cwd for git push bundle directory",
        path: temp_root.clone(),
        source,
    })?;
    Ok(cwd.join(temp_root))
}

/// Reserves a private filesystem location for a Git push bundle. The bundle
/// lives inside a `0700` directory so that even with a permissive umask, no
/// other local user can read the bundle while `git bundle create` is writing
/// it or while we are reading it back.
struct TempBundlePath {
    dir: PathBuf,
    file: PathBuf,
}

impl TempBundlePath {
    fn reserve() -> Result<Self, VmClientError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        // Absolutize before joining: a relative `TMPDIR` plus `git -C
        // <workdir>` would resolve the bundle path under <workdir> instead of
        // where we created the directory.
        let temp_root = absolutize_temp_root(std::env::temp_dir())?;
        let dir = temp_root.join(format!(".writ-vm-push-{}", uuid::Uuid::new_v4()));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&dir).map_err(|source| VmClientError::Io {
            operation: "create git push bundle directory",
            path: dir.clone(),
            source,
        })?;
        // mode(0o700) above is masked by the process umask; set_permissions
        // makes the private postcondition explicit.
        if let Err(source) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir_all(&dir);
            return Err(VmClientError::Io {
                operation: "set git push bundle directory permissions",
                path: dir,
                source,
            });
        }
        let file = dir.join("push.bundle");
        Ok(Self { dir, file })
    }

    fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for TempBundlePath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
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
            Self::ResolveHead => f.write_str("git rev-parse HEAD"),
        }
    }
}

impl std::fmt::Display for VmGitPushStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevParse => f.write_str("git rev-parse"),
            Self::BundleCreate => f.write_str("git bundle create"),
            Self::BundleListHeads => f.write_str("git bundle list-heads"),
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
    if let Ok(error) = serde_json::from_slice::<VmGitPushErrorResponse>(body) {
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
        // The sources warm stays on the session-default (proxied) substituter:
        // strictness is the *devShell* warm's contract (decision 1 of the
        // pre-warmed-devshell-cache plan).
        WorkspaceWarmMode::Sources => run_nix_flake_metadata(command, None),
        // Strict devShell warm: when the daemon advertised a pre-warm-only
        // substituter, pin *both* warm steps to it — eval input fetches and
        // closure realisation alike — so the whole warm is served from the
        // pre-warm + flake-input archives and provably never proxies upstream.
        WorkspaceWarmMode::DevShell => {
            let substituter_override = command.prewarm_substituter_url();
            run_nix_flake_metadata(command, substituter_override)?;
            run_nix_develop_true(command, substituter_override)
        }
    }
}

/// The leading `--option substituters <url>` run for a strict warm invocation,
/// or no args at all when no pre-warm substituter is in effect.
fn warm_substituter_override_args(substituter_override: Option<&str>) -> Vec<OsString> {
    substituter_override
        .map(|url| {
            nix_substituters_override_args(url)
                .into_iter()
                .map(OsString::from)
                .collect()
        })
        .unwrap_or_default()
}

fn run_nix_flake_metadata(
    command: &VmWorkspaceInitCommand,
    substituter_override: Option<&str>,
) -> Result<(), VmClientError> {
    let mut args = warm_substituter_override_args(substituter_override);
    args.extend([
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
    ]);
    run_nix_command(
        command.nix_program(),
        VmWorkspaceWarmStep::FlakeMetadata,
        args,
        command.destination(),
    )
}

fn run_nix_develop_true(
    command: &VmWorkspaceInitCommand,
    substituter_override: Option<&str>,
) -> Result<(), VmClientError> {
    let mut args = warm_substituter_override_args(substituter_override);
    args.extend(
        nix_develop_command_args(DEFAULT_DEVSHELL_ATTR)
            .into_iter()
            .map(OsString::from),
    );
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

    fn commit_one_file(git: &Path, repo_dir: &Path) -> String {
        let arg = repo_dir.to_str().unwrap();
        run_test_git(git, &["init", "--", arg]);
        run_test_git(git, &["-C", arg, "config", "user.email", "a@example.com"]);
        run_test_git(git, &["-C", arg, "config", "user.name", "a"]);
        run_test_git(git, &["-C", arg, "config", "commit.gpgsign", "false"]);
        fs::write(repo_dir.join("flake.nix"), "{}\n").unwrap();
        run_test_git(git, &["-C", arg, "add", "."]);
        run_test_git(git, &["-C", arg, "commit", "-m", "init"]);
        let head = Command::new(git)
            .args(["-C", arg, "rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(head.status.success());
        String::from_utf8_lossy(&head.stdout).trim().to_string()
    }

    fn provision_request() -> VmFlakeProvisionRequest {
        VmFlakeProvisionRequest::new(
            repo(),
            "0123456789abcdef0123456789abcdef01234567".parse().unwrap(),
        )
    }

    #[test]
    fn resolve_head_object_id_returns_the_checked_out_commit() {
        let dir = tempfile::tempdir().unwrap();
        let git = required_test_tool("git");
        let repo_dir = dir.path().join("repo");
        let expected = commit_one_file(&git, &repo_dir);

        let rev = resolve_head_object_id(&git, &repo_dir).unwrap();

        assert_eq!(rev.as_str(), expected);
    }

    #[tokio::test]
    async fn provision_best_effort_posts_repo_and_resolved_rev() {
        let dir = tempfile::tempdir().unwrap();
        let git = required_test_tool("git");
        let repo_dir = dir.path().join("repo");
        let rev = commit_one_file(&git, &repo_dir);

        let body = br#"{"status":"provisioned","request_id":"00000000-0000-0000-0000-000000000001","input_count":2,"archived_path_count":5,"archived_bytes":1024}"#;
        let (broker_url, captured) =
            serve_once(http_response("200 OK", "application/json", body)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmWorkspaceInitCommand::new(
            repo(),
            Some(repo_dir),
            WorkspaceWarmMode::Sources,
            git,
            "nix",
            None,
        )
        .unwrap();

        provision_flake_inputs_best_effort(&config, &command).await;

        let request = captured.lock().unwrap().clone();
        assert!(
            request.starts_with("POST /v1/nix/flake/provision "),
            "{request}"
        );
        assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
        assert!(request.contains(&format!(r#""rev":"{rev}""#)), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer writ-vm-secret"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn provision_best_effort_skips_when_warm_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let git = required_test_tool("git");
        let repo_dir = dir.path().join("repo");
        commit_one_file(&git, &repo_dir);
        let (broker_url, captured) = serve_once(http_response(
            "200 OK",
            "application/json",
            br#"{"status":"mirror_not_cached"}"#,
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmWorkspaceInitCommand::new(
            repo(),
            Some(repo_dir),
            WorkspaceWarmMode::None,
            git,
            "nix",
            None,
        )
        .unwrap();

        provision_flake_inputs_best_effort(&config, &command).await;

        // No warm step will run, so nothing is provisioned and the broker is
        // never contacted.
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn post_flake_provision_reads_mirror_not_cached() {
        let (broker_url, _captured) = serve_once(http_response(
            "200 OK",
            "application/json",
            br#"{"status":"mirror_not_cached"}"#,
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let outcome = post_flake_provision(&config, &provision_request())
            .await
            .unwrap();

        assert_eq!(outcome, VmFlakeProvisionResponse::MirrorNotCached);
    }

    #[tokio::test]
    async fn post_flake_provision_classifies_a_structured_refusal() {
        let body =
            br#"{"error":"unprovisionable","message":"the repository has no committed flake.lock"}"#;
        let (broker_url, _captured) = serve_once(http_response(
            "422 Unprocessable Content",
            "application/json",
            body,
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let err = post_flake_provision(&config, &provision_request())
            .await
            .unwrap_err();

        match err {
            FlakeProvisionDegrade::Status { code, message } => {
                assert_eq!(code, 422);
                assert_eq!(
                    message.as_deref(),
                    Some("the repository has no committed flake.lock")
                );
            }
            other => panic!("expected a Status degrade, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_flake_provision_tolerates_a_plain_text_disabled_endpoint() {
        let (broker_url, _captured) =
            serve_once(http_response("404 Not Found", "text/plain", b"not found")).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

        let err = post_flake_provision(&config, &provision_request())
            .await
            .unwrap_err();

        match err {
            FlakeProvisionDegrade::Status { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message, None);
            }
            other => panic!("expected a Status degrade, got {other:?}"),
        }
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
            None,
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

    /// A fake `nix` that logs each invocation's argv (one line per call) and
    /// succeeds, so warm tests can pin the exact argument envelope.
    fn write_fake_nix(dir: &Path) -> PathBuf {
        let path = dir.join("fake-nix");
        let log = dir.join("nix.log");
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> {log}\nexit 0\n",
            log = log.display()
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn warm_command(
        dir: &Path,
        warm: WorkspaceWarmMode,
        prewarm_substituter_url: Option<String>,
    ) -> VmWorkspaceInitCommand {
        let destination = dir.join("checkout");
        fs::create_dir_all(&destination).unwrap();
        VmWorkspaceInitCommand::new(
            repo(),
            Some(destination),
            warm,
            "git",
            write_fake_nix(dir),
            prewarm_substituter_url,
        )
        .unwrap()
    }

    const TEST_PREWARM_URL: &str = "http://192.168.252.1:51375/v1/nix/prewarm";

    #[test]
    fn devshell_warm_pins_both_steps_to_the_prewarm_substituter() {
        let dir = tempfile::tempdir().unwrap();
        let command = warm_command(
            dir.path(),
            WorkspaceWarmMode::DevShell,
            Some(TEST_PREWARM_URL.to_string()),
        );

        warm_workspace(&command).unwrap();

        let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
        let calls: Vec<&str> = nix_log.lines().collect();
        assert_eq!(calls.len(), 2, "{nix_log}");
        let override_prefix = format!("--option substituters {TEST_PREWARM_URL} ");
        // The strict guarantee covers the *whole* warm: eval input fetches
        // (flake metadata) and closure realisation (develop) alike.
        assert!(calls[0].starts_with(&override_prefix), "{nix_log}");
        assert!(calls[0].contains("flake metadata"), "{nix_log}");
        assert!(calls[1].starts_with(&override_prefix), "{nix_log}");
        assert!(calls[1].contains("develop"), "{nix_log}");
    }

    #[test]
    fn devshell_warm_without_prewarm_url_keeps_session_default_substituters() {
        let dir = tempfile::tempdir().unwrap();
        let command = warm_command(dir.path(), WorkspaceWarmMode::DevShell, None);

        warm_workspace(&command).unwrap();

        let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
        assert_eq!(nix_log.lines().count(), 2, "{nix_log}");
        assert!(
            !nix_log.contains("substituters"),
            "no pre-warm URL means no substituter override: {nix_log}"
        );
    }

    #[test]
    fn sources_warm_stays_on_the_session_default_substituters() {
        // Strictness is the devShell warm's contract; a sources-only warm keeps
        // the proxied default even when the daemon advertised the pre-warm URL.
        let dir = tempfile::tempdir().unwrap();
        let command = warm_command(
            dir.path(),
            WorkspaceWarmMode::Sources,
            Some(TEST_PREWARM_URL.to_string()),
        );

        warm_workspace(&command).unwrap();

        let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
        assert_eq!(nix_log.lines().count(), 1, "{nix_log}");
        assert!(!nix_log.contains("substituters"), "{nix_log}");
    }

    #[test]
    fn workspace_init_command_rejects_a_non_http_prewarm_substituter_url() {
        let err = VmWorkspaceInitCommand::new(
            repo(),
            Some(PathBuf::from("/workspace/repo")),
            WorkspaceWarmMode::DevShell,
            "git",
            "nix",
            Some("file:///srv/prewarm".to_string()),
        )
        .unwrap_err();

        assert_eq!(
            err,
            VmWorkspaceInitCommandError::UnsupportedPrewarmSubstituterUrl(
                "file:///srv/prewarm".to_string()
            )
        );
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

    fn write_fake_git_push(
        dir: &Path,
        rev_parse_oid: &str,
        bundle_bytes: &[u8],
        bundle_list_heads: &str,
    ) -> PathBuf {
        let bundle_payload = dir.join("bundle_payload");
        fs::write(&bundle_payload, bundle_bytes).unwrap();
        let list_heads_payload = dir.join("bundle_list_heads");
        // Newline-terminate so single-line outputs match the standard `git
        // bundle list-heads` format.
        let list_heads_text = if bundle_list_heads.is_empty() {
            String::new()
        } else {
            format!("{bundle_list_heads}\n")
        };
        fs::write(&list_heads_payload, list_heads_text).unwrap();
        let log = dir.join("git.log");
        let path = dir.join("fake-git-push");
        let script = format!(
            "#!/bin/sh\n\
             set -eu\n\
             printf '%s\\n' \"$*\" >> {log}\n\
             printf 'broker_url=%s\\n' \"${{WRIT_BROKER_URL-unset}}\" >> {log}\n\
             printf 'broker_token=%s\\n' \"${{WRIT_BROKER_TOKEN-unset}}\" >> {log}\n\
             if [ \"${{1:-}}\" = '-C' ]; then\n\
             printf 'cwd=%s\\n' \"$2\" >> {log}\n\
             shift 2\n\
             fi\n\
             case \"${{1:-}}\" in\n\
             rev-parse)\n\
             printf '%s\\n' '{oid}'\n\
             exit 0\n\
             ;;\n\
             bundle)\n\
             shift\n\
             case \"${{1:-}}\" in\n\
             create)\n\
             shift\n\
             out_path=\"$1\"\n\
             cp {payload} \"$out_path\"\n\
             exit 0\n\
             ;;\n\
             list-heads)\n\
             cat {list_heads}\n\
             exit 0\n\
             ;;\n\
             esac\n\
             ;;\n\
             esac\n\
             exit 64\n",
            log = shell_quote(&log),
            payload = shell_quote(&bundle_payload),
            list_heads = shell_quote(&list_heads_payload),
            oid = rev_parse_oid,
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn list_heads_line(oid: &str, branch: &str) -> String {
        format!("{oid} refs/heads/{branch}")
    }

    fn fake_oid(nibble: char) -> String {
        std::iter::repeat_n(nibble, 40).collect()
    }

    fn parse_oid(raw: &str) -> crate::vm_git::GitObjectId {
        raw.parse().unwrap()
    }

    fn parse_branch(raw: &str) -> crate::vm_git::GitBranchName {
        raw.parse().unwrap()
    }

    fn receipt_json(
        repo: &str,
        branch: &str,
        new_head: &str,
        expected_remote_head: Option<&str>,
        push_request_id: &str,
        staged_at_ms: u64,
    ) -> String {
        let expected = match expected_remote_head {
            Some(oid) => format!("\"{oid}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"repo\":\"{repo}\",\"branch\":\"{branch}\",\
             \"expected_remote_head\":{expected},\"new_head\":\"{new_head}\",\
             \"push_request_id\":\"{push_request_id}\",\"staged_at\":{staged_at_ms}}}"
        )
    }

    #[tokio::test]
    async fn push_to_broker_posts_bundle_with_metadata_and_returns_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('b');
        let expected_head = fake_oid('a');
        let bundle_bytes = b"PACK push bundle";
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            bundle_bytes,
            &list_heads_line(&new_head, "feature/x"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let body = receipt_json(
            "owner/repo",
            "feature/x",
            &new_head,
            Some(&expected_head),
            "00000000-0000-0000-0000-000000000601",
            1_700_000_000_000,
        );
        let (broker_url, captured) =
            serve_once(http_response("200 OK", "application/json", body.as_bytes())).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&expected_head)),
            workdir.clone(),
            git,
        )
        .unwrap();

        let receipt = push_to_broker(&config, &command).await.unwrap();

        assert_eq!(receipt.repo().to_string(), "owner/repo");
        assert_eq!(receipt.branch().as_str(), "feature/x");
        assert_eq!(receipt.new_head().as_str(), new_head);
        assert_eq!(
            receipt.expected_remote_head().map(|oid| oid.as_str()),
            Some(expected_head.as_str())
        );

        let request = captured.lock().unwrap().clone();
        assert!(
            request.starts_with("POST /v1/git/push HTTP/1.1"),
            "{request}"
        );
        assert!(
            request.contains("authorization: Bearer writ-vm-secret")
                || request.contains("Authorization: Bearer writ-vm-secret"),
            "{request}"
        );
        assert!(
            request.contains("application/vnd.writ.git-push-bundle"),
            "{request}"
        );
        assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
        assert!(request.contains(r#""branch":"feature/x""#), "{request}");
        assert!(
            request.contains(&format!(r#""new_head":"{new_head}""#)),
            "{request}"
        );
        assert!(
            request.contains(&format!(r#""expected_remote_head":"{expected_head}""#)),
            "{request}"
        );

        let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
        assert!(
            git_log.contains("rev-parse --verify refs/heads/feature/x^{commit}"),
            "{git_log}"
        );
        assert!(
            git_log.contains("bundle create ") && git_log.contains("refs/heads/feature/x"),
            "{git_log}"
        );
        assert!(
            git_log.contains(&format!("--not {expected_head}")),
            "{git_log}"
        );
        assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
        assert!(git_log.contains("broker_url=unset"), "{git_log}");
        assert!(git_log.contains("broker_token=unset"), "{git_log}");
    }

    #[tokio::test]
    async fn push_to_broker_omits_not_arg_when_creating_a_branch() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('c');
        let bundle_bytes = b"PACK create bundle";
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            bundle_bytes,
            &list_heads_line(&new_head, "feature/new"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let body = receipt_json(
            "owner/repo",
            "feature/new",
            &new_head,
            None,
            "00000000-0000-0000-0000-000000000602",
            1_700_000_000_000,
        );
        let (broker_url, captured) =
            serve_once(http_response("200 OK", "application/json", body.as_bytes())).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/new"),
            parse_oid(&new_head),
            None,
            workdir,
            git,
        )
        .unwrap();

        let receipt = push_to_broker(&config, &command).await.unwrap();

        assert!(receipt.expected_remote_head().is_none());
        let request = captured.lock().unwrap().clone();
        assert!(
            request.contains(r#""expected_remote_head":null"#),
            "{request}"
        );
        let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
        assert!(!git_log.contains("--not "), "{git_log}");
    }

    #[tokio::test]
    async fn push_to_broker_rejects_branch_head_mismatch_before_bundling() {
        let dir = tempfile::tempdir().unwrap();
        let claimed_head = fake_oid('b');
        let actual_head = fake_oid('d');
        let git = write_fake_git_push(dir.path(), &actual_head, b"PACK should not be sent", "");
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        // The broker mock should never be reached, but bind a listener so we
        // observe whether the client tried to send anything.
        let (broker_url, captured) = serve_once(http_response(
            "500 Internal Server Error",
            "text/plain",
            b"unexpected request",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&claimed_head),
            Some(parse_oid(&fake_oid('a'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        match err {
            VmClientError::BranchHeadMismatch {
                branch,
                expected,
                actual,
            } => {
                assert_eq!(branch, "feature/x");
                assert_eq!(expected, claimed_head);
                assert_eq!(actual, actual_head);
            }
            other => panic!("expected BranchHeadMismatch, got {other:?}"),
        }
        // No bundle command should have been spawned.
        let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
        assert!(!git_log.contains("bundle create"), "{git_log}");
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn push_to_broker_rejects_oversized_bundle_before_posting() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('e');
        // Bundle larger than the configured cap.
        let bundle_bytes = vec![0u8; 256];
        let git = write_fake_git_push(dir.path(), &new_head, &bundle_bytes, "");
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let (broker_url, captured) = serve_once(http_response(
            "500 Internal Server Error",
            "text/plain",
            b"unexpected request",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret")
            .unwrap()
            .with_max_bundle_bytes(64)
            .unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&fake_oid('a'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        assert!(matches!(
            err,
            VmClientError::BundleTooLarge {
                bytes: 256,
                max_bundle_bytes: 64,
            }
        ));
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn push_to_broker_surfaces_broker_error_message_from_push_error_response() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('f');
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            b"PACK denied bundle",
            &list_heads_line(&new_head, "feature/x"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let body = br#"{"error":"denied","message":"session is closed"}"#;
        let (broker_url, _captured) =
            serve_once(http_response("410 Gone", "application/json", body)).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&fake_oid('a'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        match err {
            VmClientError::BrokerHttp { status, message } => {
                assert_eq!(status, 410);
                assert_eq!(message, "session is closed");
            }
            other => panic!("expected BrokerHttp, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_to_broker_returns_invalid_receipt_error_for_malformed_response_body() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('a');
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            b"PACK valid bundle",
            &list_heads_line(&new_head, "feature/x"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let (broker_url, _captured) =
            serve_once(http_response("200 OK", "application/json", b"not json")).await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&fake_oid('b'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        assert!(
            matches!(err, VmClientError::BrokerInvalidReceipt(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn temp_bundle_path_uses_a_private_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let bundle = TempBundlePath::reserve().unwrap();
        let parent = bundle
            .path()
            .parent()
            .expect("bundle path must live in a directory")
            .to_path_buf();

        let metadata = fs::metadata(&parent).unwrap();
        assert!(metadata.is_dir(), "{parent:?} should be a directory");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700 on {parent:?}, got {mode:o}");

        drop(bundle);
        assert!(
            !parent.exists(),
            "temp bundle directory {parent:?} was not cleaned up on drop"
        );
    }

    #[test]
    fn temp_bundle_path_is_absolute_even_under_relative_temp_root() {
        // The reserve() postcondition: the bundle path is absolute, so handing
        // it to `git -C <workdir>` does not resolve it under <workdir>.
        let bundle = TempBundlePath::reserve().unwrap();
        assert!(
            bundle.path().is_absolute(),
            "bundle path {:?} should be absolute",
            bundle.path()
        );
    }

    #[test]
    fn absolutize_temp_root_passes_through_absolute_paths() {
        let abs = std::env::temp_dir();
        assert!(abs.is_absolute(), "test precondition: temp_dir is absolute");
        let resolved = absolutize_temp_root(abs.clone()).unwrap();
        assert_eq!(resolved, abs);
    }

    #[test]
    fn absolutize_temp_root_prepends_cwd_for_relative_paths() {
        let resolved = absolutize_temp_root(PathBuf::from("relative/tmp")).unwrap();
        assert!(resolved.is_absolute(), "{resolved:?} should be absolute");
        assert!(
            resolved.ends_with("relative/tmp"),
            "{resolved:?} should end with the original relative tail"
        );
    }

    #[test]
    fn configure_push_git_env_strips_every_repo_selection_var() {
        use std::ffi::OsStr;

        let mut command = Command::new("git");
        // Pre-set every repo-selection var so we can verify the helper
        // overrides each one with an env_remove (recorded by get_envs() as
        // `(name, None)`).
        for var in GIT_REPO_SELECTION_ENV {
            command.env(var, "/tmp/should-be-cleared");
        }
        configure_push_git_env(&mut command);

        let registered: std::collections::HashMap<&OsStr, Option<&OsStr>> =
            command.get_envs().collect();
        for var in GIT_REPO_SELECTION_ENV {
            let key = OsStr::new(var);
            assert!(
                matches!(registered.get(key), Some(None)),
                "{var} should be marked for removal"
            );
        }
        // GIT_TERMINAL_PROMPT is set positively; it is not a repo-selection
        // override, so it's not listed in GIT_REPO_SELECTION_ENV.
        assert_eq!(
            registered.get(OsStr::new("GIT_TERMINAL_PROMPT")),
            Some(&Some(OsStr::new("0")))
        );
    }

    #[tokio::test]
    async fn push_to_broker_rejects_bundle_advertising_a_different_head() {
        // Simulates a TOCTOU race: rev-parse returns new_head, but bundle
        // list-heads (i.e. what `git bundle create` actually packed) advertises
        // a different oid for the branch ref. The push must be rejected before
        // posting to the broker.
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('b');
        let drifted_head = fake_oid('d');
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            b"PACK drifted bundle",
            &list_heads_line(&drifted_head, "feature/x"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let (broker_url, captured) = serve_once(http_response(
            "500 Internal Server Error",
            "text/plain",
            b"unexpected request",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&fake_oid('a'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        match err {
            VmClientError::BundleHeadMismatch {
                branch,
                ref_name,
                expected,
                actual,
            } => {
                assert_eq!(branch, "feature/x");
                assert_eq!(ref_name, "refs/heads/feature/x");
                assert_eq!(expected, new_head);
                assert_eq!(actual, drifted_head);
            }
            other => panic!("expected BundleHeadMismatch, got {other:?}"),
        }
        assert!(
            captured.lock().unwrap().is_empty(),
            "broker should not be contacted when the bundle disagrees with new_head"
        );
    }

    #[tokio::test]
    async fn push_to_broker_rejects_bundle_missing_branch_ref() {
        // The bundle's ref list does not mention refs/heads/<branch> at all.
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('b');
        let git = write_fake_git_push(
            dir.path(),
            &new_head,
            b"PACK refless bundle",
            &list_heads_line(&new_head, "other-branch"),
        );
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let (broker_url, captured) = serve_once(http_response(
            "500 Internal Server Error",
            "text/plain",
            b"unexpected request",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            Some(parse_oid(&fake_oid('a'))),
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        match err {
            VmClientError::BundleMissingBranch { branch, ref_name } => {
                assert_eq!(branch, "feature/x");
                assert_eq!(ref_name, "refs/heads/feature/x");
            }
            other => panic!("expected BundleMissingBranch, got {other:?}"),
        }
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn push_to_broker_rejects_empty_bundle_with_dedicated_error() {
        let dir = tempfile::tempdir().unwrap();
        let new_head = fake_oid('a');
        let git = write_fake_git_push(dir.path(), &new_head, b"", "");
        let workdir = dir.path().join("repo");
        fs::create_dir_all(&workdir).unwrap();

        let (broker_url, captured) = serve_once(http_response(
            "500 Internal Server Error",
            "text/plain",
            b"unexpected request",
        ))
        .await;
        let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
        let command = VmGitPushCommand::new(
            repo(),
            parse_branch("feature/x"),
            parse_oid(&new_head),
            None,
            workdir,
            git,
        )
        .unwrap();

        let err = push_to_broker(&config, &command).await.unwrap_err();

        match err {
            VmClientError::BundleEmpty { branch } => assert_eq!(branch, "feature/x"),
            other => panic!("expected BundleEmpty, got {other:?}"),
        }
        assert!(captured.lock().unwrap().is_empty());
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
