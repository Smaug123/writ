//! Pure data types for the staged-push replay engine.
//!
//! Replay re-creates every commit between an upstream branch tip and a
//! VM-supplied bundle tip via the GitHub `blobs`/`trees`/`commits` REST
//! surface under the host App's identity, so the published commits carry
//! the Verified badge while preserving provenance back to the bundle.
//!
//! This module describes *what* a replay should do; the executor lives
//! in later commits. Keeping the description as inert data lets the
//! property tests in stage C commit 6 exercise the plan shape without
//! touching the filesystem or the network.

use std::path::{Path, PathBuf};

use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

/// A complete description of one replay operation: where the bundle lives
/// on disk, the bare repository the bundle will be ingested into, the
/// GitHub destination, and the trailers to append to each replayed
/// commit's message so reviewers can map App-owned commits back to the
/// bundle commits they were derived from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushReplayPlan {
    bundle_path: PathBuf,
    staging_repo: PathBuf,
    repo: GitCloneRepo,
    branch: GitBranchName,
    expected_remote_head: Option<GitObjectId>,
    new_head: GitObjectId,
    trailers: Vec<TrailerSource>,
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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitPushReplayPlanError {
    #[error("{field} path must not be empty")]
    EmptyPath { field: &'static str },
    #[error("{field} path must be absolute: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("bundle path and staging repository path must differ: {0}")]
    BundleEqualsStagingRepo(PathBuf),
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

impl GitPushReplayPlan {
    pub fn new(
        bundle_path: impl Into<PathBuf>,
        staging_repo: impl Into<PathBuf>,
        repo: GitCloneRepo,
        branch: GitBranchName,
        expected_remote_head: Option<GitObjectId>,
        new_head: GitObjectId,
        trailers: Vec<TrailerSource>,
    ) -> Result<Self, GitPushReplayPlanError> {
        let bundle_path = bundle_path.into();
        let staging_repo = staging_repo.into();
        require_absolute_path("bundle_path", &bundle_path)?;
        require_absolute_path("staging_repo", &staging_repo)?;
        if bundle_path == staging_repo {
            return Err(GitPushReplayPlanError::BundleEqualsStagingRepo(bundle_path));
        }
        Ok(Self {
            bundle_path,
            staging_repo,
            repo,
            branch,
            expected_remote_head,
            new_head,
            trailers,
        })
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
    use std::str::FromStr;

    use proptest::prelude::*;

    use super::*;

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

    #[test]
    fn plan_accepts_absolute_paths_and_distinct_locations() {
        let plan = GitPushReplayPlan::new(
            "/var/lib/writ/bundles/bundle.git",
            "/var/lib/writ/replay/staging.git",
            sample_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
            vec![sample_trailer()],
        )
        .unwrap();
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
    }

    #[test]
    fn plan_rejects_empty_bundle_path() {
        let err = GitPushReplayPlan::new(
            "",
            "/var/lib/writ/replay/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('b'),
            Vec::new(),
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
            "/abs/bundle.pack",
            "relative/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('c'),
            Vec::new(),
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
            "/var/lib/writ/replay/same",
            "/var/lib/writ/replay/same",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('d'),
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitPushReplayPlanError::BundleEqualsStagingRepo(_)
        ));
    }

    #[test]
    fn plan_allows_branch_creation_with_no_expected_remote_head() {
        let plan = GitPushReplayPlan::new(
            "/abs/bundle.pack",
            "/abs/staging.git",
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('e'),
            Vec::new(),
        )
        .unwrap();
        assert!(plan.expected_remote_head().is_none());
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
}
