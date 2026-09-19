//! Fixed sample values for tests that need *a* repository, object id, branch
//! or identity and do not care which. Every value here is the one most test
//! modules had already chosen; a test that asserts on a different literal
//! keeps its own.

use time::macros::datetime;

use crate::core::{RepoRef, SshSignature};
use crate::github_git_db::CommitIdentity;
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId, VmGitPushMetadata};

/// `owner/name`.
pub fn sample_repo() -> RepoRef {
    "owner/name".parse().unwrap()
}

/// `owner/repo`, as a clone target.
pub fn sample_clone_repo() -> GitCloneRepo {
    "owner/repo".parse().unwrap()
}

/// `feature/x`.
pub fn sample_branch() -> GitBranchName {
    "feature/x".parse().unwrap()
}

/// The forty-hex-digit id made of `nibble` repeated: `sample_object_id('a')`
/// is `aaaa…a`. Distinct nibbles give distinct, recognisable ids.
pub fn sample_object_id(nibble: char) -> GitObjectId {
    GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
}

/// `name <name@example.invalid>` at a fixed instant, so derived commit SHAs
/// are deterministic.
pub fn sample_identity(name: &str) -> CommitIdentity {
    CommitIdentity::new(
        name,
        format!("{name}@example.invalid"),
        datetime!(2024-01-15 10:30:45 UTC),
    )
    .expect("sample identity is valid")
}

/// A push of [`sample_clone_repo`]'s [`sample_branch`] from the `a…a` head
/// to the `b…b` head.
pub fn sample_push_metadata() -> VmGitPushMetadata {
    VmGitPushMetadata::new(
        sample_clone_repo(),
        sample_branch(),
        Some(sample_object_id('a')),
        sample_object_id('b'),
    )
}

/// A placeholder that passes [`SshSignature`]'s wire validation and nothing
/// else; for tests of the envelope shape rather than of signing.
pub fn sample_signature() -> SshSignature {
    SshSignature::try_new(
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
    )
    .unwrap()
}
