//! VM-facing Git clone wire types.
//!
//! This module validates the JSON request/response shape used between the
//! guest CLI and the host broker. Host-side bundle planning and execution live
//! in `vm_git_bundle` behind the `host` feature.
//!
//! [`RepoRef`] is the repo-wide "owner/name" shape. [`GitCloneRepo`] layers
//! GitHub-specific owner/name syntax on top because this endpoint always
//! targets GitHub repositories.

use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::core::RepoRef;

pub const VM_GIT_CLONE_PATH: &str = "/v1/git/clone";
pub const GIT_BUNDLE_CONTENT_TYPE: &str = "application/x-git-bundle";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
pub const DEFAULT_WORKSPACE_BRANCH: &str = "main";
pub const DEFAULT_DEVSHELL_ATTR: &str = ".#default";

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

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRepo(RepoRef);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GitCloneRef(String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmGitCloneErrorResponse {
    error: VmGitCloneErrorCode,
    message: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
    fn clone_route_and_bundle_content_type_are_pinned() {
        assert_eq!(VM_GIT_CLONE_PATH, "/v1/git/clone");
        assert_eq!(GIT_BUNDLE_CONTENT_TYPE, "application/x-git-bundle");
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
