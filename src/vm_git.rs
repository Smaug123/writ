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

use crate::core::{CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef};

pub const VM_GIT_CLONE_PATH: &str = "/v1/git/clone";
pub const VM_GIT_PUSH_PATH: &str = "/v1/git/push";
pub const GIT_BUNDLE_CONTENT_TYPE: &str = "application/x-git-bundle";
pub const GIT_PUSH_BUNDLE_CONTENT_TYPE: &str = "application/vnd.writ.git-push-bundle";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
pub const DEFAULT_WORKSPACE_BRANCH: &str = "main";
pub const DEFAULT_DEVSHELL_ATTR: &str = ".#default";
const GIT_PUSH_METADATA_LENGTH_BYTES: usize = 8;
const GIT_OBJECT_ID_HEX_BYTES: usize = 40;

pub fn nix_develop_command_args(attr: &str) -> Vec<String> {
    vec![
        "--option".to_string(),
        "builders".to_string(),
        String::new(),
        "--option".to_string(),
        "max-jobs".to_string(),
        "0".to_string(),
        "--option".to_string(),
        "fallback".to_string(),
        "false".to_string(),
        "develop".to_string(),
        "--no-write-lock-file".to_string(),
        attr.to_string(),
        "--command".to_string(),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneRequest {
    repo: GitCloneRepo,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    git_ref: Option<GitCloneRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitPushMetadata {
    repo: GitCloneRepo,
    branch: GitBranchName,
    expected_remote_head: GitObjectId,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitPushReceipt {
    repo: GitCloneRepo,
    branch: GitBranchName,
    old_head: GitObjectId,
    new_head: GitObjectId,
    push_request_id: String,
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
        expected_remote_head: GitObjectId,
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

    pub fn expected_remote_head(&self) -> &GitObjectId {
        &self.expected_remote_head
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

impl VmGitPushReceipt {
    pub fn new(
        repo: GitCloneRepo,
        branch: GitBranchName,
        old_head: GitObjectId,
        new_head: GitObjectId,
        push_request_id: impl Into<String>,
    ) -> Self {
        Self {
            repo,
            branch,
            old_head,
            new_head,
            push_request_id: push_request_id.into(),
        }
    }

    pub fn repo(&self) -> &GitCloneRepo {
        &self.repo
    }

    pub fn branch(&self) -> &GitBranchName {
        &self.branch
    }

    pub fn old_head(&self) -> &GitObjectId {
        &self.old_head
    }

    pub fn new_head(&self) -> &GitObjectId {
        &self.new_head
    }

    pub fn push_request_id(&self) -> &str {
        &self.push_request_id
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
    if bundle.is_empty() {
        return Err(VmGitPushBodyError::EmptyBundle);
    }
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
        if component.starts_with('.') || component.ends_with('.') {
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
            "[A-Za-z0-9_-]{1,20}".prop_map(|component| format!("feature/{component}./y")),
            Just("@".to_string()),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}:x")),
            "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix} x")),
        ]
    }

    fn invalid_git_branch_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            invalid_git_ref_strategy(),
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
            sample_object_id('1'),
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
        fn vm_push_metadata_roundtrips_any_valid_generated_fields(
            owner in owner_strategy(),
            name in repo_name_strategy(),
            branch in git_branch_strategy(),
            expected in object_id_strategy(),
            new_head in object_id_strategy(),
        ) {
            let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
            let metadata = VmGitPushMetadata::new(
                GitCloneRepo::new(repo_ref.clone()).unwrap(),
                branch.parse().unwrap(),
                expected.parse().unwrap(),
                new_head.parse().unwrap(),
            );

            let json = serde_json::to_string(&metadata).unwrap();
            let roundtrip: VmGitPushMetadata = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
            prop_assert_eq!(roundtrip, metadata);
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
    fn push_receipt_wire_shape_is_stable() {
        let receipt = VmGitPushReceipt::new(
            repo("owner", "repo"),
            "main".parse().unwrap(),
            sample_object_id('a'),
            sample_object_id('b'),
            "push-request-1",
        );
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["repo"], "owner/repo");
        assert_eq!(value["branch"], "main");
        assert_eq!(
            value["old_head"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            value["new_head"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(value["push_request_id"], "push-request-1");
        assert_eq!(
            serde_json::from_value::<VmGitPushReceipt>(value).unwrap(),
            receipt
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
        assert_eq!(GIT_BUNDLE_CONTENT_TYPE, "application/x-git-bundle");
        assert_eq!(
            GIT_PUSH_BUNDLE_CONTENT_TYPE,
            "application/vnd.writ.git-push-bundle"
        );
    }

    #[test]
    fn nix_develop_command_args_pin_no_build_no_lockfile_envelope() {
        assert_eq!(
            nix_develop_command_args(DEFAULT_DEVSHELL_ATTR),
            vec![
                "--option",
                "builders",
                "",
                "--option",
                "max-jobs",
                "0",
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
}
