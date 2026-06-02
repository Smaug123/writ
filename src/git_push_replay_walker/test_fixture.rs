//! In-memory [`GitObjectSource`] fixture for the walker tests.
//!
//! Kept `pub(crate)` so downstream test modules (e.g.
//! `git_push_promote`) reach it as
//! `crate::git_push_replay_walker::test_fixture::InMemoryGitObjectSource`.

use super::*;

/// Trivial in-memory [`GitObjectSource`]: three [`HashMap`]s,
/// one per object type. Construct via the builder methods and
/// pass to [`super::replay_commits`].
#[derive(Clone, Debug, Default)]
pub(crate) struct InMemoryGitObjectSource {
    commits: HashMap<GitObjectId, StagingCommit>,
    trees: HashMap<GitObjectId, StagingTree>,
    blobs: HashMap<GitObjectId, Vec<u8>>,
}

impl InMemoryGitObjectSource {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert_commit(&mut self, sha: GitObjectId, commit: StagingCommit) {
        self.commits.insert(sha, commit);
    }

    pub(crate) fn insert_tree(&mut self, sha: GitObjectId, tree: StagingTree) {
        self.trees.insert(sha, tree);
    }

    pub(crate) fn insert_blob(&mut self, sha: GitObjectId, content: Vec<u8>) {
        self.blobs.insert(sha, content);
    }
}

impl GitObjectSource for InMemoryGitObjectSource {
    async fn read_commit(&self, sha: &GitObjectId) -> Result<StagingCommit, GitObjectSourceError> {
        self.commits
            .get(sha)
            .cloned()
            .ok_or_else(|| GitObjectSourceError::NotFound {
                sha: sha.as_str().to_string(),
            })
    }

    async fn read_tree(&self, sha: &GitObjectId) -> Result<StagingTree, GitObjectSourceError> {
        self.trees
            .get(sha)
            .cloned()
            .ok_or_else(|| GitObjectSourceError::NotFound {
                sha: sha.as_str().to_string(),
            })
    }

    async fn read_blob(&self, sha: &GitObjectId) -> Result<Vec<u8>, GitObjectSourceError> {
        self.blobs
            .get(sha)
            .cloned()
            .ok_or_else(|| GitObjectSourceError::NotFound {
                sha: sha.as_str().to_string(),
            })
    }
}
