//! VM-facing Git wire types.
//!
//! This module validates the request/response shapes used between the guest
//! CLI and the host broker. Host-side bundle planning and execution live in
//! host-only modules behind the `host` feature.
//!
//! [`RepoRef`] is the repo-wide "owner/name" shape. [`GitCloneRepo`] layers
//! GitHub-specific owner/name syntax on top because this endpoint always
//! targets GitHub repositories.

use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use writ_core::core::{
    CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, RequestId, UnixMillis,
};

pub const VM_GIT_CLONE_PATH: &str = "/v1/git/clone";
pub const VM_GIT_PUSH_PATH: &str = "/v1/git/push";
pub const VM_FLAKE_PROVISION_PATH: &str = "/v1/nix/flake/provision";
pub const GIT_BUNDLE_CONTENT_TYPE: &str = "application/x-git-bundle";
pub const GIT_PUSH_BUNDLE_CONTENT_TYPE: &str = "application/vnd.writ.git-push-bundle";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
pub const DEFAULT_WORKSPACE_BRANCH: &str = "main";
pub const DEFAULT_DEVSHELL_ATTR: &str = ".#default";

/// Environment variable through which the daemon injects the broker base URL
/// into the guest. The guest CLI reads it; the host daemon sets it. It lives
/// here — a host↔guest wire contract — rather than in the guest client, so the
/// host can name it without depending on the guest client module.
pub const VM_BROKER_URL_ENV: &str = "WRIT_BROKER_URL";
/// Environment variable through which the daemon injects the broker bearer
/// token into the guest. See [`VM_BROKER_URL_ENV`] for why it lives here.
pub const VM_BROKER_TOKEN_ENV: &str = "WRIT_BROKER_TOKEN";
/// The strict, pre-warm-only substituter URL, injected by the daemon exactly
/// when the broker serves a pre-warm cache dir. When present, the devShell
/// warm's nix invocations replace their substituters with this URL, so the warm
/// never reaches the upstream-proxying cache view.
pub const VM_NIX_PREWARM_URL_ENV: &str = "WRIT_NIX_PREWARM_URL";
const GIT_PUSH_METADATA_LENGTH_BYTES: usize = 8;
const GIT_OBJECT_ID_HEX_BYTES: usize = 40;

/// Local build jobs the no-egress guest may run while warming the devShell.
///
/// The motivating case is `allowSubstitutes = false` / `preferLocalBuild`
/// setup-hook derivations (e.g. `cargoHelperFunctionsHook`): Nix refuses to
/// *substitute* these and insists on building them, so under a strictly
/// substitute-only (`max-jobs = 0`) guest they are unrealisable and the warm
/// fails even when every other path substitutes fine. Their inputs are
/// themselves substitutable, so building them needs no egress.
///
/// This deliberately widens the warm envelope from "substitute only" to
/// "substitute, plus build anything that has no substituter". Substitution is
/// still always preferred, and `fallback` stays `false` so a *failed*
/// substitution (a substituter that has the path but errors) is a hard error
/// rather than a from-source rebuild. But a path with *no* substituter — a
/// local package or `runCommand` in the devShell — will now build locally
/// during warm rather than failing fast. That residual is bounded by the
/// no-egress sandbox (any build needing to fetch sources/FODs still fails) and
/// by the workspace-bootstrap timeout; `builders` stays empty so no work is
/// offloaded. A guest that must never run flake build code needs the closure
/// pre-realised in an egress builder (the deferred egress-VM provisioner)
/// instead, which is a separate, larger change.
///
/// Kept at 1 to bound the work and keep guest resource use predictable.
const GUEST_DEVSHELL_WARM_MAX_JOBS: &str = "1";

pub fn nix_develop_command_args(attr: &str) -> Vec<String> {
    vec![
        "--option".to_string(),
        "builders".to_string(),
        String::new(),
        "--option".to_string(),
        "max-jobs".to_string(),
        GUEST_DEVSHELL_WARM_MAX_JOBS.to_string(),
        "--option".to_string(),
        "fallback".to_string(),
        "false".to_string(),
        "develop".to_string(),
        "--no-write-lock-file".to_string(),
        attr.to_string(),
        "--command".to_string(),
    ]
}

/// Replace the session's substituters for one `nix` invocation, pinning it to
/// `substituter_url` — the broker's pre-warm-only `/v1/nix/prewarm` view during
/// a strict devShell warm. `substituters` (not `extra-substituters`) so the
/// session nix.conf default (the upstream-proxying `/v1/nix/cache`) is
/// *removed*, not augmented: a path absent from the pre-warmed closure then
/// fails the warm instead of silently substituting from the public upstream.
/// Scoped to the warm's own invocations; the session nix.conf — and so the
/// agent's later Nix usage — keeps the proxied default.
pub fn nix_substituters_override_args(substituter_url: &str) -> Vec<String> {
    vec![
        "--option".to_string(),
        "substituters".to_string(),
        substituter_url.to_string(),
    ]
}

/// The *strict* devShell warm realisation: `nix print-dev-env` under the same
/// envelope as [`nix_develop_command_args`].
///
/// A strict warm must demand exactly the closure the pre-warm builder signed —
/// and the builder realises via `nix print-dev-env --profile`. `nix develop`
/// demands MORE than that closure: it also resolves an interactive shell
/// (`nixpkgs#bashInteractive` from the flake's nixpkgs input), which is not in
/// the dev-env closure, so under a pre-warm-only substituter it 404s and
/// `max-jobs = 1` then attempts a from-source bash build whose fixed-output
/// fetches need egress (verified empirically: a fresh-store, egress-denied
/// `nix develop` against a pre-warmed cache queued the whole bash+bison build
/// graph). `print-dev-env` realises the identical environment without spawning
/// a shell, so warm-demands ≡ signed-closure holds by construction. The
/// agent-run wrapper still uses `nix develop` on the session's proxied
/// substituter, where the shell substitutes from the public upstream as today.
pub fn nix_print_dev_env_command_args(attr: &str) -> Vec<String> {
    vec![
        "--option".to_string(),
        "builders".to_string(),
        String::new(),
        "--option".to_string(),
        "max-jobs".to_string(),
        GUEST_DEVSHELL_WARM_MAX_JOBS.to_string(),
        "--option".to_string(),
        "fallback".to_string(),
        "false".to_string(),
        "print-dev-env".to_string(),
        "--no-write-lock-file".to_string(),
        attr.to_string(),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneRequest {
    repo: GitCloneRepo,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    git_ref: Option<GitCloneRef>,
}

/// Coordinates the guest sends to provision a flake's committed, locked inputs
/// from the broker's retained `(repo, rev)` mirror. The guest sends only these
/// coordinates — never flake content: the broker re-derives the checkout from
/// its own mirror, so the request surface stays a repository and a commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmFlakeProvisionRequest {
    repo: GitCloneRepo,
    rev: GitObjectId,
}

/// Successful outcome of a provision request. `MirrorNotCached` is a success,
/// not an error: no mirror is retained for `(repo, rev)` (retention is off, or
/// the clone that would have populated it has not run), so the guest proceeds
/// without the optimisation rather than failing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VmFlakeProvisionResponse {
    Provisioned {
        request_id: RequestId,
        input_count: u64,
        archived_path_count: u64,
        archived_bytes: u64,
    },
    MirrorNotCached,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmFlakeProvisionErrorResponse {
    error: VmFlakeProvisionErrorCode,
    message: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmFlakeProvisionErrorCode {
    /// The request body was not a valid provision request.
    InvalidRequest,
    /// The session is not active (unknown or closed).
    Denied,
    /// The repository's committed lock cannot be auto-provisioned: no
    /// `flake.lock`, or an input the broker refuses to fetch (local, private,
    /// credential-requiring, or unpinned). A property of the repository, not
    /// the broker — the guest degrades and lets the warm step surface the
    /// original failure.
    Unprovisionable,
    /// The broker failed to provision the inputs (a git, nix, or I/O failure
    /// on the host).
    ProvisionFailed,
}

impl VmFlakeProvisionRequest {
    pub fn new(repo: GitCloneRepo, rev: GitObjectId) -> Self {
        Self { repo, rev }
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn rev(&self) -> &GitObjectId {
        &self.rev
    }
}

impl VmFlakeProvisionErrorResponse {
    pub fn new(error: VmFlakeProvisionErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }

    pub fn error(&self) -> VmFlakeProvisionErrorCode {
        self.error
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Wire-validated push metadata. `expected_remote_head` is required to be
/// present on the wire — see the manual `Deserialize` impl below — so that
/// a stale or buggy client cannot drop the key and silently mean "branch
/// creation". `None` is the honest representation of "the guest is
/// creating a new branch": there is no upstream head to fast-forward
/// from, and persisting that distinction is what lets the staging area
/// separate genuine no-op pushes from branch-creation pushes during
/// human review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VmGitPushMetadata {
    repo: GitCloneRepo,
    branch: GitBranchName,
    expected_remote_head: Option<GitObjectId>,
    new_head: GitObjectId,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VmGitPushRequest {
    metadata: VmGitPushMetadata,
    bundle: Vec<u8>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRepo(RepoRef);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRef(String);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitBranchName(String);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitObjectId(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VmGitPushBodyLimits {
    max_body_bytes: usize,
    max_metadata_bytes: usize,
    max_bundle_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneErrorResponse {
    error: VmGitCloneErrorCode,
    message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitPushErrorResponse {
    error: VmGitPushErrorCode,
    message: String,
}

/// Receipt returned to the guest after a push has been written to the host
/// staging area. The broker does not contact GitHub during a VM-initiated
/// push: the bundle and metadata sit on the host, awaiting human-driven
/// promotion. The receipt therefore carries `staged_at` (the wall-clock
/// time at which the staging entry was durable) rather than any GitHub-
/// observed result; `expected_remote_head` is `None` exactly when the push
/// is creating the branch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VmGitPushStagedReceipt {
    repo: GitCloneRepo,
    branch: GitBranchName,
    expected_remote_head: Option<GitObjectId>,
    new_head: GitObjectId,
    push_request_id: RequestId,
    staged_at: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentVmWorkspaceBootstrap {
    pub repo: GitCloneRepo,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub destination: Option<PathBuf>,
    #[serde(default)]
    pub warm: WorkspaceWarmMode,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceWarmMode {
    None,
    Sources,
    #[default]
    DevShell,
}

pub fn default_workspace_destination(repo: &GitCloneRepo) -> PathBuf {
    PathBuf::from(DEFAULT_WORKSPACE_ROOT).join(&repo.as_repo_ref().name)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmGitCloneErrorCode {
    InvalidRequest,
    Denied,
    CloneFailed,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmGitPushErrorCode {
    InvalidRequest,
    Denied,
    ValidationFailed,
    PushFailed,
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
pub enum GitBranchNameError {
    #[error("Git branch name must not be empty")]
    Empty,
    #[error("Git branch name is too long; maximum is 255 bytes")]
    TooLong,
    #[error("Git branch name must not be a full ref: {0}")]
    FullRef(String),
    #[error("Git branch name must not be HEAD")]
    Head,
    #[error("Git branch name must not start with '-'")]
    LeadingDash,
    #[error("Git branch name must not start, end, or contain a double slash")]
    SlashPlacement,
    #[error("Git branch name contains a forbidden sequence: {0}")]
    ForbiddenSequence(&'static str),
    #[error("Git branch name contains a forbidden byte: {0:?}")]
    ForbiddenByte(char),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitObjectIdError {
    #[error("Git object ID must be exactly 40 hexadecimal bytes, got {0}")]
    WrongLength(usize),
    #[error("Git object ID contains a non-hexadecimal byte: {0:?}")]
    NonHexByte(char),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmGitPushBodyLimitsError {
    #[error("maximum VM Git push body size must be greater than zero")]
    EmptyMaxBodyBytes,
    #[error("maximum VM Git push metadata size must be greater than zero")]
    EmptyMaxMetadataBytes,
    #[error("maximum VM Git push bundle size must be greater than zero")]
    EmptyMaxBundleBytes,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmGitPushRequestError {
    #[error("Git push bundle must not be empty")]
    EmptyBundle,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmGitPushBodyError {
    #[error("VM Git push body is too large: {bytes} bytes exceeds limit {max_body_bytes}")]
    BodyTooLarge { bytes: usize, max_body_bytes: usize },
    #[error("VM Git push body is missing the 8-byte metadata length prefix")]
    MissingMetadataLength,
    #[error("VM Git push metadata length {metadata_bytes} exceeds body length {body_bytes}")]
    TruncatedMetadata {
        metadata_bytes: usize,
        body_bytes: usize,
    },
    #[error("VM Git push metadata is too large: {bytes} bytes exceeds limit {max_metadata_bytes}")]
    MetadataTooLarge {
        bytes: usize,
        max_metadata_bytes: usize,
    },
    #[error("VM Git push metadata length cannot fit in memory: {0}")]
    MetadataLengthOverflow(u64),
    #[error("invalid VM Git push metadata JSON: {0}")]
    InvalidMetadata(String),
    #[error("Git push bundle must not be empty")]
    EmptyBundle,
    #[error("Git push bundle is too large: {bytes} bytes exceeds limit {max_bundle_bytes}")]
    BundleTooLarge {
        bytes: usize,
        max_bundle_bytes: usize,
    },
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
}

impl VmGitPushMetadata {
    pub fn new(
        repo: GitCloneRepo,
        branch: GitBranchName,
        expected_remote_head: Option<GitObjectId>,
        new_head: GitObjectId,
    ) -> Self {
        Self {
            repo,
            branch,
            expected_remote_head,
            new_head,
        }
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn branch(&self) -> &GitBranchName {
        &self.branch
    }

    pub fn expected_remote_head(&self) -> Option<&GitObjectId> {
        self.expected_remote_head.as_ref()
    }

    pub fn new_head(&self) -> &GitObjectId {
        &self.new_head
    }

    pub fn authorization_request(&self) -> CapabilityRequest {
        CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: self.repo.as_repo_ref().clone(),
        })
    }
}

// Hand-rolled because serde's derive treats `Option<T>` fields as having
// an implicit `None` default on missing keys, which would let a stale or
// buggy client drop `expected_remote_head` and have it silently mean
// "branch creation". Tracking key presence at the map level is the only
// way to distinguish a present-and-null value from an absent key.
impl<'de> Deserialize<'de> for VmGitPushMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(
            "VmGitPushMetadata",
            VM_GIT_PUSH_METADATA_FIELDS,
            VmGitPushMetadataVisitor,
        )
    }
}

const VM_GIT_PUSH_METADATA_FIELDS: &[&str] =
    &["repo", "branch", "expected_remote_head", "new_head"];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum VmGitPushMetadataField {
    Repo,
    Branch,
    ExpectedRemoteHead,
    NewHead,
}

struct VmGitPushMetadataVisitor;

impl<'de> serde::de::Visitor<'de> for VmGitPushMetadataVisitor {
    type Value = VmGitPushMetadata;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("struct VmGitPushMetadata")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let mut repo: Option<GitCloneRepo> = None;
        let mut branch: Option<GitBranchName> = None;
        let mut expected_remote_head: Option<Option<GitObjectId>> = None;
        let mut new_head: Option<GitObjectId> = None;
        while let Some(key) = map.next_key::<VmGitPushMetadataField>()? {
            match key {
                VmGitPushMetadataField::Repo => {
                    if repo.is_some() {
                        return Err(A::Error::duplicate_field("repo"));
                    }
                    repo = Some(map.next_value()?);
                }
                VmGitPushMetadataField::Branch => {
                    if branch.is_some() {
                        return Err(A::Error::duplicate_field("branch"));
                    }
                    branch = Some(map.next_value()?);
                }
                VmGitPushMetadataField::ExpectedRemoteHead => {
                    if expected_remote_head.is_some() {
                        return Err(A::Error::duplicate_field("expected_remote_head"));
                    }
                    expected_remote_head = Some(map.next_value::<Option<GitObjectId>>()?);
                }
                VmGitPushMetadataField::NewHead => {
                    if new_head.is_some() {
                        return Err(A::Error::duplicate_field("new_head"));
                    }
                    new_head = Some(map.next_value()?);
                }
            }
        }
        Ok(VmGitPushMetadata {
            repo: repo.ok_or_else(|| A::Error::missing_field("repo"))?,
            branch: branch.ok_or_else(|| A::Error::missing_field("branch"))?,
            expected_remote_head: expected_remote_head
                .ok_or_else(|| A::Error::missing_field("expected_remote_head"))?,
            new_head: new_head.ok_or_else(|| A::Error::missing_field("new_head"))?,
        })
    }
}

impl VmGitPushRequest {
    pub fn new(
        metadata: VmGitPushMetadata,
        bundle: Vec<u8>,
    ) -> Result<Self, VmGitPushRequestError> {
        if bundle.is_empty() {
            return Err(VmGitPushRequestError::EmptyBundle);
        }
        Ok(Self { metadata, bundle })
    }

    pub fn metadata(&self) -> &VmGitPushMetadata {
        &self.metadata
    }

    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    pub fn into_parts(self) -> (VmGitPushMetadata, Vec<u8>) {
        (self.metadata, self.bundle)
    }
}

impl std::fmt::Debug for VmGitPushRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmGitPushRequest")
            .field("metadata", &self.metadata)
            .field("bundle_bytes", &self.bundle.len())
            .finish()
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

impl GitBranchName {
    pub fn new(raw: impl Into<String>) -> Result<Self, GitBranchNameError> {
        let raw = raw.into();
        validate_git_branch_name(&raw)?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_heads_ref(&self) -> String {
        format!("refs/heads/{}", self.0)
    }
}

impl std::fmt::Debug for GitBranchName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GitBranchName").field(&self.0).finish()
    }
}

impl std::fmt::Display for GitBranchName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for GitBranchName {
    type Err = GitBranchNameError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl Serialize for GitBranchName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitBranchName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl GitObjectId {
    pub fn new(raw: impl Into<String>) -> Result<Self, GitObjectIdError> {
        let raw = raw.into();
        validate_git_object_id(&raw)?;
        Ok(Self(raw.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GitObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GitObjectId").field(&self.0).finish()
    }
}

impl std::fmt::Display for GitObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for GitObjectId {
    type Err = GitObjectIdError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl Serialize for GitObjectId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl VmGitPushBodyLimits {
    pub fn new(
        max_body_bytes: usize,
        max_metadata_bytes: usize,
        max_bundle_bytes: usize,
    ) -> Result<Self, VmGitPushBodyLimitsError> {
        if max_body_bytes == 0 {
            return Err(VmGitPushBodyLimitsError::EmptyMaxBodyBytes);
        }
        if max_metadata_bytes == 0 {
            return Err(VmGitPushBodyLimitsError::EmptyMaxMetadataBytes);
        }
        if max_bundle_bytes == 0 {
            return Err(VmGitPushBodyLimitsError::EmptyMaxBundleBytes);
        }
        Ok(Self {
            max_body_bytes,
            max_metadata_bytes,
            max_bundle_bytes,
        })
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn max_metadata_bytes(&self) -> usize {
        self.max_metadata_bytes
    }

    pub fn max_bundle_bytes(&self) -> usize {
        self.max_bundle_bytes
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

impl VmGitPushErrorResponse {
    pub fn new(error: VmGitPushErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }

    pub fn error(&self) -> VmGitPushErrorCode {
        self.error
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl VmGitPushStagedReceipt {
    pub fn new(
        repo: GitCloneRepo,
        branch: GitBranchName,
        expected_remote_head: Option<GitObjectId>,
        new_head: GitObjectId,
        push_request_id: RequestId,
        staged_at: UnixMillis,
    ) -> Self {
        Self {
            repo,
            branch,
            expected_remote_head,
            new_head,
            push_request_id,
            staged_at,
        }
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn branch(&self) -> &GitBranchName {
        &self.branch
    }

    pub fn expected_remote_head(&self) -> Option<&GitObjectId> {
        self.expected_remote_head.as_ref()
    }

    pub fn new_head(&self) -> &GitObjectId {
        &self.new_head
    }

    pub fn push_request_id(&self) -> RequestId {
        self.push_request_id
    }

    pub fn staged_at(&self) -> UnixMillis {
        self.staged_at
    }
}

// See `VmGitPushMetadata` above: hand-rolled to require explicit
// `expected_remote_head` presence on the wire rather than letting serde's
// implicit Option default mean "branch creation".
impl<'de> Deserialize<'de> for VmGitPushStagedReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(
            "VmGitPushStagedReceipt",
            VM_GIT_PUSH_STAGED_RECEIPT_FIELDS,
            VmGitPushStagedReceiptVisitor,
        )
    }
}

const VM_GIT_PUSH_STAGED_RECEIPT_FIELDS: &[&str] = &[
    "repo",
    "branch",
    "expected_remote_head",
    "new_head",
    "push_request_id",
    "staged_at",
];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum VmGitPushStagedReceiptField {
    Repo,
    Branch,
    ExpectedRemoteHead,
    NewHead,
    PushRequestId,
    StagedAt,
}

struct VmGitPushStagedReceiptVisitor;

impl<'de> serde::de::Visitor<'de> for VmGitPushStagedReceiptVisitor {
    type Value = VmGitPushStagedReceipt;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("struct VmGitPushStagedReceipt")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let mut repo: Option<GitCloneRepo> = None;
        let mut branch: Option<GitBranchName> = None;
        let mut expected_remote_head: Option<Option<GitObjectId>> = None;
        let mut new_head: Option<GitObjectId> = None;
        let mut push_request_id: Option<RequestId> = None;
        let mut staged_at: Option<UnixMillis> = None;
        while let Some(key) = map.next_key::<VmGitPushStagedReceiptField>()? {
            match key {
                VmGitPushStagedReceiptField::Repo => {
                    if repo.is_some() {
                        return Err(A::Error::duplicate_field("repo"));
                    }
                    repo = Some(map.next_value()?);
                }
                VmGitPushStagedReceiptField::Branch => {
                    if branch.is_some() {
                        return Err(A::Error::duplicate_field("branch"));
                    }
                    branch = Some(map.next_value()?);
                }
                VmGitPushStagedReceiptField::ExpectedRemoteHead => {
                    if expected_remote_head.is_some() {
                        return Err(A::Error::duplicate_field("expected_remote_head"));
                    }
                    expected_remote_head = Some(map.next_value::<Option<GitObjectId>>()?);
                }
                VmGitPushStagedReceiptField::NewHead => {
                    if new_head.is_some() {
                        return Err(A::Error::duplicate_field("new_head"));
                    }
                    new_head = Some(map.next_value()?);
                }
                VmGitPushStagedReceiptField::PushRequestId => {
                    if push_request_id.is_some() {
                        return Err(A::Error::duplicate_field("push_request_id"));
                    }
                    push_request_id = Some(map.next_value()?);
                }
                VmGitPushStagedReceiptField::StagedAt => {
                    if staged_at.is_some() {
                        return Err(A::Error::duplicate_field("staged_at"));
                    }
                    staged_at = Some(map.next_value()?);
                }
            }
        }
        Ok(VmGitPushStagedReceipt {
            repo: repo.ok_or_else(|| A::Error::missing_field("repo"))?,
            branch: branch.ok_or_else(|| A::Error::missing_field("branch"))?,
            expected_remote_head: expected_remote_head
                .ok_or_else(|| A::Error::missing_field("expected_remote_head"))?,
            new_head: new_head.ok_or_else(|| A::Error::missing_field("new_head"))?,
            push_request_id: push_request_id
                .ok_or_else(|| A::Error::missing_field("push_request_id"))?,
            staged_at: staged_at.ok_or_else(|| A::Error::missing_field("staged_at"))?,
        })
    }
}

pub fn parse_vm_git_push_request_body(
    body: &[u8],
    limits: VmGitPushBodyLimits,
) -> Result<VmGitPushRequest, VmGitPushBodyError> {
    if body.len() > limits.max_body_bytes() {
        return Err(VmGitPushBodyError::BodyTooLarge {
            bytes: body.len(),
            max_body_bytes: limits.max_body_bytes(),
        });
    }
    if body.len() < GIT_PUSH_METADATA_LENGTH_BYTES {
        return Err(VmGitPushBodyError::MissingMetadataLength);
    }

    let metadata_len_bytes: [u8; GIT_PUSH_METADATA_LENGTH_BYTES] = body
        [..GIT_PUSH_METADATA_LENGTH_BYTES]
        .try_into()
        .expect("slice length checked above");
    let metadata_bytes_u64 = u64::from_be_bytes(metadata_len_bytes);
    let metadata_bytes = usize::try_from(metadata_bytes_u64)
        .map_err(|_| VmGitPushBodyError::MetadataLengthOverflow(metadata_bytes_u64))?;
    if metadata_bytes > limits.max_metadata_bytes() {
        return Err(VmGitPushBodyError::MetadataTooLarge {
            bytes: metadata_bytes,
            max_metadata_bytes: limits.max_metadata_bytes(),
        });
    }

    let metadata_end = GIT_PUSH_METADATA_LENGTH_BYTES
        .checked_add(metadata_bytes)
        .ok_or(VmGitPushBodyError::MetadataLengthOverflow(
            metadata_bytes_u64,
        ))?;
    if metadata_end > body.len() {
        return Err(VmGitPushBodyError::TruncatedMetadata {
            metadata_bytes,
            body_bytes: body.len(),
        });
    }

    let metadata = serde_json::from_slice::<VmGitPushMetadata>(
        &body[GIT_PUSH_METADATA_LENGTH_BYTES..metadata_end],
    )
    .map_err(|err| VmGitPushBodyError::InvalidMetadata(err.to_string()))?;
    let bundle = body[metadata_end..].to_vec();
    if bundle.len() > limits.max_bundle_bytes() {
        return Err(VmGitPushBodyError::BundleTooLarge {
            bytes: bundle.len(),
            max_bundle_bytes: limits.max_bundle_bytes(),
        });
    }
    VmGitPushRequest::new(metadata, bundle).map_err(|err| match err {
        VmGitPushRequestError::EmptyBundle => VmGitPushBodyError::EmptyBundle,
    })
}

pub fn encode_vm_git_push_request_body(
    request: &VmGitPushRequest,
) -> Result<Vec<u8>, serde_json::Error> {
    let metadata = serde_json::to_vec(request.metadata())?;
    let mut body = Vec::with_capacity(
        GIT_PUSH_METADATA_LENGTH_BYTES + metadata.len() + request.bundle().len(),
    );
    body.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    body.extend_from_slice(&metadata);
    body.extend_from_slice(request.bundle());
    Ok(body)
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
        if component.starts_with('.') {
            return Err(GitCloneRefError::ForbiddenSequence("."));
        }
        if component.ends_with(".lock") {
            return Err(GitCloneRefError::ForbiddenSequence(".lock"));
        }
    }
    Ok(())
}

fn validate_git_branch_name(raw: &str) -> Result<(), GitBranchNameError> {
    if raw.is_empty() {
        return Err(GitBranchNameError::Empty);
    }
    if raw.len() > 255 {
        return Err(GitBranchNameError::TooLong);
    }
    if raw == "HEAD" {
        return Err(GitBranchNameError::Head);
    }
    if raw.starts_with("refs/") {
        return Err(GitBranchNameError::FullRef(raw.to_string()));
    }
    if raw.starts_with('-') {
        return Err(GitBranchNameError::LeadingDash);
    }
    if raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        return Err(GitBranchNameError::SlashPlacement);
    }
    if raw.ends_with('.') {
        return Err(GitBranchNameError::ForbiddenSequence("."));
    }
    if raw == "@" {
        return Err(GitBranchNameError::ForbiddenSequence("@"));
    }
    for sequence in ["..", "@{"] {
        if raw.contains(sequence) {
            return Err(GitBranchNameError::ForbiddenSequence(sequence));
        }
    }
    for ch in raw.chars() {
        if ch.is_ascii_control()
            || ch.is_ascii_whitespace()
            || matches!(ch, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        {
            return Err(GitBranchNameError::ForbiddenByte(ch));
        }
        if !ch.is_ascii() {
            return Err(GitBranchNameError::ForbiddenByte(ch));
        }
    }
    for component in raw.split('/') {
        if component.starts_with('.') || component.ends_with('.') {
            return Err(GitBranchNameError::ForbiddenSequence("."));
        }
        if component.ends_with(".lock") {
            return Err(GitBranchNameError::ForbiddenSequence(".lock"));
        }
    }
    Ok(())
}

fn validate_git_object_id(raw: &str) -> Result<(), GitObjectIdError> {
    if raw.len() != GIT_OBJECT_ID_HEX_BYTES {
        return Err(GitObjectIdError::WrongLength(raw.len()));
    }
    for ch in raw.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(GitObjectIdError::NonHexByte(ch));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn repo(owner: &str, name: &str) -> GitCloneRepo {
        format!("{owner}/{name}").parse().unwrap()
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

    fn git_branch_strategy() -> impl Strategy<Value = String> {
        git_ref_strategy()
    }

    fn git_branch_oracle_char_strategy() -> impl Strategy<Value = char> {
        prop_oneof![
            ascii_alnum(),
            Just('/'),
            Just('.'),
            Just('_'),
            Just('-'),
            Just('@'),
            Just('{'),
            Just(' '),
            Just('~'),
            Just('^'),
            Just(':'),
            Just('?'),
            Just('*'),
            Just('['),
            Just('\\'),
        ]
    }

    fn git_branch_oracle_candidate_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            git_branch_strategy(),
            invalid_git_branch_strategy(),
            prop::collection::vec(git_branch_oracle_char_strategy(), 0..40)
                .prop_map(|chars| chars.into_iter().collect()),
        ]
    }

    fn object_id_strategy() -> impl Strategy<Value = String> {
        "[0-9a-fA-F]{40}"
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

    fn invalid_git_branch_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            invalid_git_ref_strategy(),
            "[A-Za-z0-9_-]{1,20}".prop_map(|component| format!("feature/{component}./y")),
            Just("HEAD".to_string()),
            git_ref_strategy().prop_map(|branch| format!("refs/heads/{branch}")),
        ]
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        std::iter::repeat_n(nibble, GIT_OBJECT_ID_HEX_BYTES)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn push_metadata() -> VmGitPushMetadata {
        VmGitPushMetadata::new(
            repo("owner", "repo"),
            "feature/x".parse().unwrap(),
            Some(sample_object_id('1')),
            sample_object_id('2'),
        )
    }

    fn push_request() -> VmGitPushRequest {
        VmGitPushRequest::new(push_metadata(), b"bundle-bytes".to_vec()).unwrap()
    }

    fn push_limits() -> VmGitPushBodyLimits {
        VmGitPushBodyLimits::new(4096, 1024, 1024).unwrap()
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
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("{name} not found on PATH for vm_git tests");
    }

    fn git_check_ref_format_branch_accepts(raw: &str) -> bool {
        Command::new(required_test_tool("git"))
            .args(["check-ref-format", "--branch", raw])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap_or_else(|err| panic!("failed to run git check-ref-format: {err}"))
            .status
            .success()
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
            prop_assert_eq!(parsed.as_str(), raw.as_str());
        }

        #[test]
        fn generated_invalid_git_refs_are_rejected(raw in invalid_git_ref_strategy()) {
            prop_assert!(
                raw.parse::<GitCloneRef>().is_err(),
                "accepted invalid ref {raw:?}"
            );
        }

        #[test]
        fn git_branch_roundtrips_any_valid_generated_name(raw in git_branch_strategy()) {
            let parsed = GitBranchName::new(raw.clone()).unwrap();
            let reparsed: GitBranchName = parsed.as_str().parse().unwrap();
            prop_assert_eq!(reparsed, parsed.clone());
            prop_assert_eq!(parsed.as_str(), raw.as_str());
            prop_assert_eq!(parsed.as_heads_ref(), format!("refs/heads/{raw}"));
        }

        #[test]
        fn generated_invalid_git_branches_are_rejected(raw in invalid_git_branch_strategy()) {
            prop_assert!(
                raw.parse::<GitBranchName>().is_err(),
                "accepted invalid branch {raw:?}"
            );
        }

        #[test]
        fn git_branch_validator_matches_git_check_ref_format_branch_and_broker_rules(
            raw in git_branch_oracle_candidate_strategy(),
        ) {
            let git_accepts = git_check_ref_format_branch_accepts(&raw);
            let expected = git_accepts
                && !raw.starts_with("refs/")
                && raw != "@"
                && !raw.split('/').any(|component| component.ends_with('.'));
            let actual = raw.parse::<GitBranchName>().is_ok();

            prop_assert_eq!(
                actual,
                expected,
                "validator disagrees with git check-ref-format plus broker branch rules for {:?}",
                raw
            );
        }

        #[test]
        fn object_ids_roundtrip_and_normalize_to_lowercase(raw in object_id_strategy()) {
            let parsed: GitObjectId = raw.parse().unwrap();
            prop_assert_eq!(parsed.as_str(), raw.to_ascii_lowercase());
            let json = serde_json::to_string(&parsed).unwrap();
            let roundtrip: GitObjectId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtrip, parsed);
        }

        #[test]
        fn flake_provision_request_roundtrips_any_valid_generated_coordinates(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            rev in object_id_strategy(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let request = VmFlakeProvisionRequest::new(
                GitCloneRepo::new(repo_ref.clone()).unwrap(),
                rev.parse().unwrap(),
            );

            let json = serde_json::to_string(&request).unwrap();
            let roundtrip: VmFlakeProvisionRequest = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
            prop_assert_eq!(roundtrip, request);
        }

        #[test]
        fn vm_push_metadata_roundtrips_any_valid_generated_fields(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            branch in git_branch_strategy(),
            expected in proptest::option::of(object_id_strategy()),
            new_head in object_id_strategy(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let metadata = VmGitPushMetadata::new(
                GitCloneRepo::new(repo_ref.clone()).unwrap(),
                branch.parse().unwrap(),
                expected.map(|raw| raw.parse().unwrap()),
                new_head.parse().unwrap(),
            );

            let json = serde_json::to_string(&metadata).unwrap();
            let roundtrip: VmGitPushMetadata = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
            prop_assert_eq!(roundtrip, metadata);
        }

        #[test]
        fn vm_push_staged_receipt_roundtrips_any_valid_generated_fields(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            branch in git_branch_strategy(),
            expected in proptest::option::of(object_id_strategy()),
            new_head in object_id_strategy(),
            staged_at in any::<i64>(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let receipt = VmGitPushStagedReceipt::new(
                GitCloneRepo::new(repo_ref.clone()).unwrap(),
                branch.parse().unwrap(),
                expected.map(|raw| raw.parse().unwrap()),
                new_head.parse().unwrap(),
                RequestId::new(),
                UnixMillis::from_millis(staged_at),
            );

            let json = serde_json::to_string(&receipt).unwrap();
            let roundtrip: VmGitPushStagedReceipt = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
            prop_assert_eq!(roundtrip, receipt);
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
    fn flake_provision_request_wire_shape_is_repo_and_rev() {
        let request = VmFlakeProvisionRequest::new(
            repo("owner", "repo.name"),
            "0123456789abcdef0123456789abcdef01234567".parse().unwrap(),
        );
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["repo"], "owner/repo.name");
        assert_eq!(value["rev"], "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(
            serde_json::from_value::<VmFlakeProvisionRequest>(value).unwrap(),
            request
        );
    }

    #[test]
    fn flake_provision_response_is_tagged_by_status() {
        let request_id = RequestId::new();
        let provisioned = VmFlakeProvisionResponse::Provisioned {
            request_id,
            input_count: 3,
            archived_path_count: 7,
            archived_bytes: 4096,
        };
        let value = serde_json::to_value(&provisioned).unwrap();
        assert_eq!(value["status"], "provisioned");
        assert_eq!(value["input_count"], 3);
        assert_eq!(value["archived_path_count"], 7);
        assert_eq!(value["archived_bytes"], 4096);
        assert_eq!(value["request_id"], request_id.to_string());
        assert_eq!(
            serde_json::from_value::<VmFlakeProvisionResponse>(value).unwrap(),
            provisioned
        );

        let not_cached = serde_json::to_value(VmFlakeProvisionResponse::MirrorNotCached).unwrap();
        assert_eq!(not_cached["status"], "mirror_not_cached");
        assert_eq!(
            serde_json::from_value::<VmFlakeProvisionResponse>(not_cached).unwrap(),
            VmFlakeProvisionResponse::MirrorNotCached
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
    fn malformed_branches_are_rejected_before_planning() {
        for raw in [
            "",
            "HEAD",
            "refs/heads/main",
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
            assert!(raw.parse::<GitBranchName>().is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn malformed_object_ids_are_rejected_before_planning() {
        for raw in [
            "",
            "1",
            "111111111111111111111111111111111111111",
            "11111111111111111111111111111111111111111",
            "111111111111111111111111111111111111111g",
            "111111111111111111111111111111111111111/",
        ] {
            assert!(raw.parse::<GitObjectId>().is_err(), "accepted {raw:?}");
        }
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
    fn push_error_response_wire_shape_is_stable() {
        let response =
            VmGitPushErrorResponse::new(VmGitPushErrorCode::ValidationFailed, "bad ancestry");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["error"], "validation_failed");
        assert_eq!(value["message"], "bad ancestry");
        assert_eq!(
            serde_json::from_value::<VmGitPushErrorResponse>(value).unwrap(),
            response
        );
    }

    #[test]
    fn push_metadata_wire_shape_and_authorization_request_are_stable() {
        let metadata = push_metadata();
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(value["repo"], "owner/repo");
        assert_eq!(value["branch"], "feature/x");
        assert_eq!(
            value["expected_remote_head"],
            "1111111111111111111111111111111111111111"
        );
        assert_eq!(
            value["new_head"],
            "2222222222222222222222222222222222222222"
        );
        assert_eq!(
            serde_json::from_value::<VmGitPushMetadata>(value).unwrap(),
            metadata
        );

        match metadata.authorization_request() {
            CapabilityRequest::GitHub(GitHubRequest::Contents { access, repo }) => {
                assert_eq!(access, GitHubAccess::Write);
                assert_eq!(repo.to_string(), "owner/repo");
            }
            other => panic!("unexpected authorization request: {other:?}"),
        }
    }

    #[test]
    fn push_metadata_branch_creation_serialises_expected_head_as_null() {
        let metadata = VmGitPushMetadata::new(
            repo("owner", "repo"),
            "feature/x".parse().unwrap(),
            None,
            sample_object_id('2'),
        );
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(value["expected_remote_head"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_value::<VmGitPushMetadata>(value).unwrap(),
            metadata
        );
    }

    #[test]
    fn push_metadata_rejects_missing_expected_remote_head_key() {
        let json = serde_json::json!({
            "repo": "owner/repo",
            "branch": "feature/x",
            "new_head": "2222222222222222222222222222222222222222",
        });
        let result = serde_json::from_value::<VmGitPushMetadata>(json);
        assert!(
            result.is_err(),
            "missing expected_remote_head key should be rejected (got {:?})",
            result.ok()
        );
    }

    #[test]
    fn push_request_body_parser_splits_metadata_and_bundle() {
        let request = push_request();
        let body = encode_vm_git_push_request_body(&request).unwrap();

        let parsed = parse_vm_git_push_request_body(&body, push_limits()).unwrap();

        assert_eq!(parsed, request);
    }

    #[test]
    fn push_request_body_parser_rejects_malformed_envelopes() {
        let request = push_request();
        let body = encode_vm_git_push_request_body(&request).unwrap();

        assert!(matches!(
            parse_vm_git_push_request_body(&body[..7], push_limits()),
            Err(VmGitPushBodyError::MissingMetadataLength)
        ));

        let mut truncated = 20u64.to_be_bytes().to_vec();
        truncated.extend_from_slice(b"{}");
        assert!(matches!(
            parse_vm_git_push_request_body(&truncated, push_limits()),
            Err(VmGitPushBodyError::TruncatedMetadata { .. })
        ));

        let mut invalid_metadata = 1u64.to_be_bytes().to_vec();
        invalid_metadata.extend_from_slice(b"{");
        invalid_metadata.extend_from_slice(b"bundle");
        assert!(matches!(
            parse_vm_git_push_request_body(&invalid_metadata, push_limits()),
            Err(VmGitPushBodyError::InvalidMetadata(_))
        ));

        let metadata = serde_json::to_vec(&push_metadata()).unwrap();
        let mut empty_bundle = (metadata.len() as u64).to_be_bytes().to_vec();
        empty_bundle.extend_from_slice(&metadata);
        assert!(matches!(
            parse_vm_git_push_request_body(&empty_bundle, push_limits()),
            Err(VmGitPushBodyError::EmptyBundle)
        ));
    }

    #[test]
    fn push_request_body_parser_enforces_independent_limits() {
        let request = push_request();
        let body = encode_vm_git_push_request_body(&request).unwrap();

        assert!(matches!(
            parse_vm_git_push_request_body(
                &body,
                VmGitPushBodyLimits::new(body.len() - 1, 1024, 1024).unwrap()
            ),
            Err(VmGitPushBodyError::BodyTooLarge { .. })
        ));

        assert!(matches!(
            parse_vm_git_push_request_body(&body, VmGitPushBodyLimits::new(4096, 1, 1024).unwrap()),
            Err(VmGitPushBodyError::MetadataTooLarge { .. })
        ));

        assert!(matches!(
            parse_vm_git_push_request_body(&body, VmGitPushBodyLimits::new(4096, 1024, 1).unwrap()),
            Err(VmGitPushBodyError::BundleTooLarge { .. })
        ));
    }

    #[test]
    fn push_staged_receipt_wire_shape_is_stable() {
        let push_request_id = RequestId::new();
        let staged_at = UnixMillis::from_millis(1_700_000_000_123);
        let receipt = VmGitPushStagedReceipt::new(
            repo("owner", "repo"),
            "main".parse().unwrap(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
            push_request_id,
            staged_at,
        );
        assert_eq!(receipt.push_request_id(), push_request_id);
        assert_eq!(receipt.staged_at(), staged_at);
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["repo"], "owner/repo");
        assert_eq!(value["branch"], "main");
        assert_eq!(
            value["expected_remote_head"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            value["new_head"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            value["push_request_id"],
            serde_json::json!(push_request_id.to_string())
        );
        assert_eq!(value["staged_at"], staged_at.as_millis());
        assert_eq!(
            serde_json::from_value::<VmGitPushStagedReceipt>(value).unwrap(),
            receipt
        );
    }

    #[test]
    fn push_staged_receipt_serialises_branch_creation_expected_head_as_null() {
        let receipt = VmGitPushStagedReceipt::new(
            repo("owner", "repo"),
            "feature/x".parse().unwrap(),
            None,
            sample_object_id('b'),
            RequestId::new(),
            UnixMillis::from_millis(1_700_000_000_123),
        );
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["expected_remote_head"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_value::<VmGitPushStagedReceipt>(value).unwrap(),
            receipt
        );
    }

    #[test]
    fn push_staged_receipt_rejects_missing_expected_remote_head_key() {
        let json = serde_json::json!({
            "repo": "owner/repo",
            "branch": "feature/x",
            "new_head": "2222222222222222222222222222222222222222",
            "push_request_id": RequestId::new().to_string(),
            "staged_at": 1_700_000_000_123_i64,
        });
        let result = serde_json::from_value::<VmGitPushStagedReceipt>(json);
        assert!(
            result.is_err(),
            "missing expected_remote_head key should be rejected (got {:?})",
            result.ok()
        );
    }

    #[test]
    fn push_request_debug_reports_bundle_length_not_bundle_bytes() {
        let request =
            VmGitPushRequest::new(push_metadata(), b"secret bundle bytes".to_vec()).unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("bundle_bytes"));
        assert!(debug.contains("19"));
        assert!(!debug.contains("secret bundle bytes"));
    }

    #[test]
    fn clone_route_and_bundle_content_type_are_pinned() {
        assert_eq!(VM_GIT_CLONE_PATH, "/v1/git/clone");
        assert_eq!(VM_GIT_PUSH_PATH, "/v1/git/push");
        assert_eq!(VM_FLAKE_PROVISION_PATH, "/v1/nix/flake/provision");
        assert_eq!(GIT_BUNDLE_CONTENT_TYPE, "application/x-git-bundle");
        assert_eq!(
            GIT_PUSH_BUNDLE_CONTENT_TYPE,
            "application/vnd.writ.git-push-bundle"
        );
    }

    #[test]
    fn nix_develop_command_args_pin_bounded_build_no_lockfile_envelope() {
        assert_eq!(
            nix_develop_command_args(DEFAULT_DEVSHELL_ATTR),
            vec![
                "--option",
                "builders",
                "",
                "--option",
                "max-jobs",
                GUEST_DEVSHELL_WARM_MAX_JOBS,
                "--option",
                "fallback",
                "false",
                "develop",
                "--no-write-lock-file",
                ".#default",
                "--command",
            ]
        );
    }

    #[test]
    fn nix_print_dev_env_command_args_pin_bounded_build_no_lockfile_no_shell_envelope() {
        // Identical envelope to the develop warm, but `print-dev-env`: the
        // strict warm must never invoke `nix develop`'s interactive-shell
        // resolution (nixpkgs#bashInteractive), which demands paths outside
        // the pre-warmed closure.
        assert_eq!(
            nix_print_dev_env_command_args(DEFAULT_DEVSHELL_ATTR),
            vec![
                "--option",
                "builders",
                "",
                "--option",
                "max-jobs",
                GUEST_DEVSHELL_WARM_MAX_JOBS,
                "--option",
                "fallback",
                "false",
                "print-dev-env",
                "--no-write-lock-file",
                ".#default",
            ]
        );
    }

    #[test]
    fn nix_substituters_override_args_pin_full_replacement_envelope() {
        // `substituters`, not `extra-substituters`: the strict warm must
        // *replace* the session default, or the upstream-proxying substituter
        // would remain reachable and the override would enforce nothing.
        assert_eq!(
            nix_substituters_override_args("http://192.168.252.1:51375/v1/nix/prewarm"),
            vec![
                "--option",
                "substituters",
                "http://192.168.252.1:51375/v1/nix/prewarm",
            ]
        );
    }

    /// Extract the `--option <key> <value>` pairs from the leading run of the
    /// arg vector (before the `develop` subcommand).
    fn nix_develop_options(attr: &str) -> std::collections::HashMap<String, String> {
        let args = nix_develop_command_args(attr);
        let develop = args.iter().position(|a| a == "develop").unwrap();
        let mut options = std::collections::HashMap::new();
        let mut i = 0;
        while i < develop {
            assert_eq!(args[i], "--option", "non-option arg before `develop`");
            options.insert(args[i + 1].clone(), args[i + 2].clone());
            i += 3;
        }
        options
    }

    #[test]
    fn nix_develop_warm_substitutes_first_but_permits_bounded_local_build() {
        let options = nix_develop_options(DEFAULT_DEVSHELL_ATTR);

        // No remote builders, and a failed *substitution* is a hard error
        // rather than a from-source rebuild (which could need egress).
        assert_eq!(options.get("builders").map(String::as_str), Some(""));
        assert_eq!(options.get("fallback").map(String::as_str), Some("false"));

        // `max-jobs` must be non-zero so the guest can locally realise the
        // handful of `allowSubstitutes = false` / `preferLocalBuild` setup-hook
        // derivations (e.g. `cargoHelperFunctionsHook`) that Nix refuses to
        // substitute. At zero, those are unrealisable and the warm fails.
        let max_jobs: u32 = options
            .get("max-jobs")
            .expect("max-jobs option is set")
            .parse()
            .expect("max-jobs is an integer");
        assert!(max_jobs > 0, "max-jobs must be non-zero, got {max_jobs}");
    }
}
