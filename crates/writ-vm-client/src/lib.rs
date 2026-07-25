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

use writ_agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunStreamUpload,
    VmAgentRunConfigResponse, VmAgentRunOutcomeUpload, vm_agent_run_config_path,
    vm_agent_run_outcome_path,
};
use writ_core::bearer::is_bearer_token_byte;
use writ_core::process_spawn;
use writ_vm_git::{
    DEFAULT_DEVSHELL_ATTR, DEFAULT_WORKSPACE_BRANCH, GIT_BUNDLE_CONTENT_TYPE,
    GIT_PUSH_BUNDLE_CONTENT_TYPE, GitBranchName, GitCloneRef, GitCloneRepo, GitObjectId,
    VM_FLAKE_PROVISION_PATH, VM_GIT_CLONE_PATH, VM_GIT_PUSH_PATH, VM_HTTP_CONTRACT_HEADER,
    VM_HTTP_CONTRACT_VERSION, VM_SESSION_PATH, VmFlakeProvisionErrorResponse,
    VmFlakeProvisionRequest, VmFlakeProvisionResponse, VmGitCloneErrorResponse, VmGitCloneRequest,
    VmGitPushErrorResponse, VmGitPushMetadata, VmGitPushRequest, VmGitPushStagedReceipt,
    WorkspaceWarmMode, default_workspace_destination, encode_vm_git_push_request_body,
    nix_develop_command_args, nix_print_dev_env_command_args, nix_substituters_override_args,
};

// The broker/pre-warm env-var names are a host↔guest wire contract, so they
// live in `writ-vm-git`; re-exported here for existing `vm_client::…` callers.
pub use writ_vm_git::{VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV, VM_NIX_PREWARM_URL_ENV};

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
    #[error(
        "the guest and the broker disagree on the VM HTTP contract: this guest speaks version \
         {guest}, the broker speaks {broker}. {}",
        contract_mismatch_remedy(*guest, *broker)
    )]
    ContractMismatch { guest: u32, broker: u32 },
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

    /// Begin a request to the broker, carrying both credentials this guest owes
    /// it: the session bearer token, and the contract version it speaks.
    ///
    /// Every call site used to assemble these by hand, which made "does this
    /// request declare everything it must?" a per-site question with seven
    /// answers. The broker now *refuses* a request on one of its own routes that
    /// omits [`VM_HTTP_CONTRACT_HEADER`], so a forgotten header is no longer a
    /// missing check but a broken endpoint — hence one constructor, and no
    /// public way to reach a bare [`Url`].
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .request(method, self.endpoint(path))
            .bearer_auth(self.bearer_token().as_str())
            .header(VM_HTTP_CONTRACT_HEADER, VM_HTTP_CONTRACT_VERSION)
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
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
    let response = config.get(VM_SESSION_PATH).send().await?;
    let response = require_success(response).await?;
    response
        .json::<serde_json::Value>()
        .await
        .map_err(VmClientError::from)
}

/// Which side is behind, and therefore what to do about it.
///
/// The version ordering says who is stale: telling an operator to rebuild the
/// guest when the *broker* is the old one sends them round a loop that changes
/// nothing (the rebuild produces the same guest, and does not restart the
/// daemon).
fn contract_mismatch_remedy(guest: u32, broker: u32) -> String {
    if broker < guest {
        format!(
            "The broker is the older side: restart the `writd` daemon on the host from this \
             build (and, for `broker_placement = vm`, rebuild its image with `{}`).",
            writ_vm_git::BROKER_IMAGE_REBUILD_COMMAND,
        )
    } else {
        format!(
            "The guest is the older side: rebuild its image with `{}`.",
            writ_vm_git::GUEST_IMAGE_REBUILD_COMMAND,
        )
    }
}

/// Refuse to talk to a broker whose contract version differs from this guest's.
///
/// Called once at startup, before any real work: a run that dies halfway through
/// having already pushed a branch is worse than one that never starts. The guest
/// is the side that checks because it is the side that can be stale — a rebuilt
/// host launches whatever image is loaded in the container store.
///
/// Reads only [`writ_vm_git::VmHttpContract::version`] out of the session response, so a
/// newer broker's extra fields cannot stop an older guest from *diagnosing* the
/// mismatch.
pub async fn verify_broker_contract(config: &VmClientConfig) -> Result<(), VmClientError> {
    let response = config.get(VM_SESSION_PATH).send().await?;
    let response = require_success(response).await?;
    let contract = response.json::<writ_vm_git::VmHttpContract>().await?;
    if contract.version == writ_vm_git::VM_HTTP_CONTRACT_VERSION {
        return Ok(());
    }
    Err(VmClientError::ContractMismatch {
        guest: writ_vm_git::VM_HTTP_CONTRACT_VERSION,
        broker: contract.version,
    })
}

pub async fn fetch_agent_run_config(
    config: &VmClientConfig,
    run_id: AgentRunId,
) -> Result<(AgentPrompt, String), VmClientError> {
    let response = config.get(&vm_agent_run_config_path(run_id)).send().await?;
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
    let response = config
        .post(&vm_agent_run_outcome_path(outcome.run_id))
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
        writ_vm_git::VmGitPushRequestError::EmptyBundle => VmClientError::BundleEmpty {
            branch: command.branch().as_str().to_string(),
        },
    })?;
    let body = encode_vm_git_push_request_body(&request)
        .expect("encoded VmGitPushMetadata is always valid JSON");
    let response = config
        .post(VM_GIT_PUSH_PATH)
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
    let response = config
        .post(VM_FLAKE_PROVISION_PATH)
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
    let response = config.post(VM_GIT_CLONE_PATH).json(request).send().await?;
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
        retained_sha256_hex: writ_agent_run::sha256_hex(&retained),
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
    // The strict warm realises via `print-dev-env`, never `nix develop`: the
    // latter additionally resolves an interactive shell (nixpkgs#bashInteractive)
    // outside the pre-warmed closure, which the pre-warm-only substituter
    // cannot serve (see `nix_print_dev_env_command_args`). The non-strict warm
    // keeps `nix develop --command true` byte-for-byte, with the shell
    // substituting through the upstream-capable proxy as before.
    let mut args = warm_substituter_override_args(substituter_override);
    match substituter_override {
        Some(_) => {
            args.extend(
                nix_print_dev_env_command_args(DEFAULT_DEVSHELL_ATTR)
                    .into_iter()
                    .map(OsString::from),
            );
        }
        None => {
            args.extend(
                nix_develop_command_args(DEFAULT_DEVSHELL_ATTR)
                    .into_iter()
                    .map(OsString::from),
            );
            args.push(OsString::from("true"));
        }
    }
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
mod tests;
