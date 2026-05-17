//! Per-commit GitHub upload walker for staged push replay.
//!
//! After [`crate::git_push_replay::prepare_staging_repo`] +
//! [`crate::git_push_replay::ingest_bundle`], the staging repo holds
//! every git object the bundle declared, with the bundle's commits
//! reachable from the bundle's new tip. This module walks a
//! caller-supplied list of those commits in topological order and
//! uploads each one's blobs, trees, and the commit object itself to
//! GitHub via the Git Database REST API, returning the App-side SHA the
//! published branch will point at.
//!
//! The walker is parameterised over a [`GitObjectSource`] so its core
//! orchestration can be exercised against an in-memory fixture without
//! shelling out to git. A real implementation backed by
//! `git cat-file --batch` lands in a later commit.
//!
//! [`plan_branch_creation_via_rev_list`] handles topology discovery for
//! the branch-creation case. It shells out to
//! `git rev-list --topo-order --reverse --boundary ^<default_head>
//! <bundle_tip>` against the staging repo and parses the output into
//! the new-commits list and the boundary-commit seed. The
//! `^<default_head>` exclusion is what makes this approach correct
//! across the cases the in-walker parent-pointer DFS could not handle:
//!
//! * The bundle's tip forks from an older default-branch commit
//!   (current default head has advanced past the fork point). The
//!   merge-base is excluded with everything reachable from it, so the
//!   walker only emits the genuinely new commits.
//! * The bundle's tip is a merge whose parents have different ages
//!   on the default branch. Each ancestor reachable from
//!   `default_head` is excluded regardless of which merge parent
//!   leads there, so no already-published commit gets re-uploaded.
//!
//! Pre-conditions: the staging repo must already contain
//! `default_head` reachable as a commit object (typically because the
//! orchestrator fetched it before calling the planner) plus the full
//! bundle history that the agent shipped. The default-head fetch must
//! retrieve full ancestry, not a shallow `--depth=1` clone: rev-list
//! treats shallow boundaries as roots, which would silently truncate
//! the merge-base computation and surface a wrong rejection. The
//! planner runs `rev-parse --is-shallow-repository` first and refuses
//! a shallow repo via [`BranchCreationPlanError::ShallowStagingRepo`].
//!
//! The fast-forward case is the same shape with the upstream tip in
//! place of `default_head`; that integration lands in a later slice.
//!
//! Signing (producing the detached PGP/SSH signature that drives
//! GitHub's Verified badge) is also deferred: this walker always passes
//! `signature: None` to [`crate::github_git_db::GitDataClient::create_commit`].
//! The slot for it is the `signature` field on
//! [`crate::github_git_db::CommitRequest`].
//!
//! ## Topological pre-condition
//!
//! `replay_commits` takes its commit list in parents-before-children
//! order. Any parent that is *not* in the list must already be present
//! in the seed [`ShaMap`] (typically the upstream tip on a fast-forward,
//! whose App-side SHA equals its bundle-side SHA). Encountering a
//! parent that satisfies neither condition is reported as
//! [`ReplayError::UnmappedParent`] rather than silently producing a
//! commit with no parent.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::clean_git::{self, CleanGitError, CleanGitInvocation, clean_git_config_env};
use crate::core::RepoRef;
use crate::git_push_replay::TrailerSource;
use crate::github_git_db::{
    CommitIdentity, CommitRequest, GitDataClient, GitDataError, TreeEntry, TreeEntryKind,
};
use crate::vm_git::{GitObjectId, GitObjectIdError};

/// One commit, as the walker needs to see it after parsing out of the
/// staging repository's object database.
///
/// Parents are listed in the order Git stores them on the commit
/// object — left-first for ordinary commits, first-parent first for
/// merges. The walker preserves that order on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingCommit {
    pub tree: GitObjectId,
    pub parents: Vec<GitObjectId>,
    pub author: CommitIdentity,
    pub committer: CommitIdentity,
    pub message: String,
}

/// One tree, as the walker needs to see it after parsing out of the
/// staging repository's object database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingTree {
    pub entries: Vec<StagingTreeEntry>,
}

/// One row in a [`StagingTree`].
///
/// `kind` jointly fixes the file mode and the object type (blob vs.
/// subtree vs. submodule); see [`TreeEntryKind`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingTreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
    pub sha: GitObjectId,
}

/// Read-only access to commits, trees, and blobs in the staging
/// repository, addressed by bundle SHA.
///
/// The walker reads every object by SHA — it never traverses refs or
/// HEAD. That keeps tests trivial (an in-memory `HashMap` is enough)
/// and the production implementation (`git cat-file --batch`) is just
/// another implementation of the same trait.
pub trait GitObjectSource {
    fn read_commit(
        &self,
        sha: &GitObjectId,
    ) -> impl Future<Output = Result<StagingCommit, GitObjectSourceError>>;

    fn read_tree(
        &self,
        sha: &GitObjectId,
    ) -> impl Future<Output = Result<StagingTree, GitObjectSourceError>>;

    fn read_blob(
        &self,
        sha: &GitObjectId,
    ) -> impl Future<Output = Result<Vec<u8>, GitObjectSourceError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum GitObjectSourceError {
    #[error("object {sha} not found in staging repo")]
    NotFound { sha: String },
    #[error("object {sha} is malformed: {reason}")]
    Malformed { sha: String, reason: String },
    #[error(
        "object {sha} reports size {size} bytes which exceeds the configured per-object limit of {max} bytes"
    )]
    ObjectTooLarge { sha: String, size: u64, max: u64 },
    #[error("git object source has been poisoned by an earlier failure and is no longer usable")]
    Poisoned,
    #[error("object access failed: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

/// Bundle SHA → App SHA mapping built up during replay.
///
/// Three sub-maps, one per object type, because the wire object the
/// walker plugs the SHA into is type-specific: a remapped blob SHA
/// goes into a tree's `blob` entry, a remapped tree SHA goes into a
/// tree's `tree` entry or a commit's root, and a remapped commit SHA
/// goes into a commit's `parents` list.
///
/// The commit sub-map is also the seed slot. On a fast-forward
/// replay, the caller pre-inserts the upstream tip's commit SHA as
/// mapping to itself, so when a bundle commit names that SHA as its
/// parent the walker finds an App-side mapping without needing to
/// upload it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShaMap {
    blobs: HashMap<GitObjectId, GitObjectId>,
    trees: HashMap<GitObjectId, GitObjectId>,
    commits: HashMap<GitObjectId, GitObjectId>,
}

impl ShaMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a commit SHA that already exists on the App side under
    /// the same SHA — typically the upstream tip on a fast-forward
    /// replay, whose objects are unchanged between bundle and remote.
    pub fn seed_commit_identity(&mut self, sha: GitObjectId) {
        self.commits.insert(sha.clone(), sha);
    }

    /// Look up the App-side SHA for a blob seen during walk. `None`
    /// means the blob has not been uploaded yet.
    pub fn blob(&self, bundle: &GitObjectId) -> Option<&GitObjectId> {
        self.blobs.get(bundle)
    }

    /// Look up the App-side SHA for a tree seen during walk.
    pub fn tree(&self, bundle: &GitObjectId) -> Option<&GitObjectId> {
        self.trees.get(bundle)
    }

    /// Look up the App-side SHA for a commit (either seeded or
    /// uploaded during walk).
    pub fn commit(&self, bundle: &GitObjectId) -> Option<&GitObjectId> {
        self.commits.get(bundle)
    }

    pub fn commit_count(&self) -> usize {
        self.commits.len()
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("read from staging repo failed: {0}")]
    Source(#[from] GitObjectSourceError),
    #[error("GitHub Git Data request failed: {0}")]
    GitDb(#[from] GitDataError),
    #[error(
        "bundle commit {bundle_sha} names parent {parent_sha} which has no App-side mapping \
         (not in the seed map, not earlier in the topo-sorted commit list)"
    )]
    UnmappedParent {
        bundle_sha: String,
        parent_sha: String,
    },
}

/// Walk a topo-sorted list of bundle commit SHAs and upload each
/// commit's full object closure to GitHub.
///
/// Returns the App-side SHA of the *last* commit in `commits`, which
/// is the SHA the replay caller will publish under
/// `refs/heads/<branch>`. The returned [`ShaMap`] reflects every
/// blob, tree, and commit the walk created or seeded, so callers
/// that want to record replay accounting (e.g. how many commits were
/// uploaded versus reused) have the data without rebuilding it.
///
/// Pre-conditions:
///
/// * `commits` is non-empty.
/// * `commits` is topologically sorted — every commit's parents
///   appear either earlier in `commits` or as a key in `seed`.
/// * Each commit in `commits` is reachable from the bundle tip in the
///   staging repo (so `source.read_commit` will find it).
pub async fn replay_commits<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    commits: &[GitObjectId],
    seed: ShaMap,
    trailers: &[TrailerSource],
) -> Result<(GitObjectId, ShaMap), ReplayError> {
    let mut map = seed;
    let mut last_app_sha: Option<GitObjectId> = None;
    for bundle_sha in commits {
        let app_sha =
            replay_one_commit(client, repo, source, &mut map, bundle_sha, trailers).await?;
        last_app_sha = Some(app_sha);
    }
    let final_sha = last_app_sha.expect(
        "replay_commits pre-condition: commits is non-empty; \
         the caller produced this list from rev-list and must not call us with an empty list",
    );
    Ok((final_sha, map))
}

/// Upload one commit and its required object closure. Idempotent
/// per-object: if a blob, tree, or commit's App-side SHA is already
/// in `map`, no upload is performed.
async fn replay_one_commit<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    map: &mut ShaMap,
    bundle_sha: &GitObjectId,
    trailers: &[TrailerSource],
) -> Result<GitObjectId, ReplayError> {
    if let Some(existing) = map.commit(bundle_sha) {
        return Ok(existing.clone());
    }
    let commit = source.read_commit(bundle_sha).await?;
    upload_tree_closure(client, repo, source, map, &commit.tree).await?;
    let root_app_sha = map
        .tree(&commit.tree)
        .cloned()
        .expect("tree closure upload guarantees root tree is mapped");

    let mut parents = Vec::with_capacity(commit.parents.len());
    for parent in &commit.parents {
        let app_parent =
            map.commit(parent)
                .cloned()
                .ok_or_else(|| ReplayError::UnmappedParent {
                    bundle_sha: bundle_sha.as_str().to_string(),
                    parent_sha: parent.as_str().to_string(),
                })?;
        parents.push(app_parent);
    }

    let message = render_message(&commit.message, trailers, bundle_sha);
    let request = CommitRequest {
        tree: &root_app_sha,
        parents: &parents,
        message: &message,
        author: &commit.author,
        committer: &commit.committer,
        signature: None,
    };
    let new_sha = client.create_commit(repo, &request).await?;
    map.commits.insert(bundle_sha.clone(), new_sha.clone());
    Ok(new_sha)
}

/// Upload every blob and subtree reachable from `root` (in
/// post-order) and the root tree itself, inserting App-side SHAs
/// into `map`. Subsequent calls naming an already-uploaded subtree
/// short-circuit on the `map` lookup.
///
/// Iterative DFS rather than recursion: each tree gets two stack
/// entries, one `Enter` that reads its children and pushes them,
/// and one `Exit` that uploads it after its children have been
/// processed. This keeps the future type concrete and bounded — no
/// `Box::pin` boxing per recursion level, no risk of stack overflow
/// on pathological tree depth.
async fn upload_tree_closure<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    map: &mut ShaMap,
    root: &GitObjectId,
) -> Result<(), ReplayError> {
    enum Phase {
        Enter,
        Exit(StagingTree),
    }

    let mut stack: Vec<(GitObjectId, Phase)> = vec![(root.clone(), Phase::Enter)];
    while let Some((sha, phase)) = stack.pop() {
        match phase {
            Phase::Enter => {
                if map.tree(&sha).is_some() {
                    continue;
                }
                let tree = source.read_tree(&sha).await?;
                // Exit must run *after* every child has been
                // processed. Push exit first so children pushed
                // after it pop first.
                stack.push((sha, Phase::Exit(tree.clone())));
                for entry in &tree.entries {
                    if matches!(entry.kind, TreeEntryKind::Subtree)
                        && map.tree(&entry.sha).is_none()
                    {
                        stack.push((entry.sha.clone(), Phase::Enter));
                    }
                }
            }
            Phase::Exit(tree) => {
                if map.tree(&sha).is_some() {
                    // Pushed twice (cycle through a shared subtree
                    // visited from two paths). Already uploaded by
                    // the time we popped this Exit; nothing more
                    // to do.
                    continue;
                }
                let mut wire_entries = Vec::with_capacity(tree.entries.len());
                for entry in tree.entries {
                    let app_sha = match entry.kind {
                        TreeEntryKind::Blob
                        | TreeEntryKind::Executable
                        | TreeEntryKind::Symlink => {
                            ensure_blob_uploaded(client, repo, source, map, &entry.sha).await?
                        }
                        TreeEntryKind::Subtree => map
                            .tree(&entry.sha)
                            .cloned()
                            .expect("DFS contract: subtree was uploaded before its parent Exit"),
                        TreeEntryKind::Submodule => {
                            // Submodule entries name a commit in a
                            // *different* repository. We don't have
                            // that object in our staging repo and
                            // we won't be creating it on GitHub
                            // either — the SHA is plumbed through
                            // verbatim, which is what the
                            // submodule consumer expects.
                            entry.sha.clone()
                        }
                    };
                    wire_entries.push(TreeEntry {
                        path: entry.path,
                        kind: entry.kind,
                        sha: app_sha,
                    });
                }
                let new_sha = client.create_tree(repo, &wire_entries).await?;
                map.trees.insert(sha, new_sha);
            }
        }
    }
    Ok(())
}

async fn ensure_blob_uploaded<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    map: &mut ShaMap,
    bundle_sha: &GitObjectId,
) -> Result<GitObjectId, ReplayError> {
    if let Some(existing) = map.blob(bundle_sha) {
        return Ok(existing.clone());
    }
    let content = source.read_blob(bundle_sha).await?;
    let new_sha = client.create_blob(repo, &content).await?;
    map.blobs.insert(bundle_sha.clone(), new_sha.clone());
    Ok(new_sha)
}

#[derive(Debug, thiserror::Error)]
pub enum BranchCreationPlanError {
    /// The `git rev-list` subprocess itself failed (unknown SHA,
    /// missing staging repo, IO error, exit-status non-zero).
    ///
    /// We stringify the underlying `CleanGitError` rather than
    /// re-exporting it: the clean-git module is `pub(crate)` and
    /// publishing one of its variants here would force the entire
    /// hardening helper out into the public surface. Callers in
    /// this crate that need structured information can match on
    /// the underlying invocation; downstream consumers only care
    /// about the human-readable text.
    #[error("`git rev-list` failed: {0}")]
    Git(String),
    #[error(
        "`git rev-list --boundary` emitted a line that does not parse as a commit SHA: \
         {line:?} ({reason})"
    )]
    InvalidRevListOutput { line: String, reason: String },
    /// The bundle's history shares no commits with the App-side
    /// default branch. Either the agent submitted an orphan branch
    /// or the bundle was constructed from a different upstream than
    /// the one we're replaying against.
    ///
    /// Detected by inspecting the boundary commits `rev-list
    /// --boundary` emits: every interesting commit reachable from
    /// `bundle_tip` is genuinely new (none of the bundle's ancestors
    /// are reachable from `default_head`). The walker would
    /// otherwise upload an orphan history under the App identity,
    /// which the replay contract explicitly forbids.
    #[error(
        "bundle history is disjoint from the default branch head {default_head}: \
         `git rev-list --boundary ^{default_head} {bundle_tip}` found no boundary commits, \
         which means no ancestor of {bundle_tip} is reachable from the default branch"
    )]
    DisjointHistory {
        default_head: String,
        bundle_tip: String,
    },
    /// The staging repo is shallow (it has a `.git/shallow` file).
    ///
    /// `rev-list ^<default_head> <bundle_tip>` cannot traverse past a
    /// shallow boundary: Git treats the shallow commit as a root, so
    /// any ancestor older than the shallow depth is invisible. If the
    /// bundle forked from default at a commit older than the shallow
    /// depth, the planner would falsely report `DisjointHistory` (or
    /// worse, succeed and upload commits that already exist on the
    /// App side).
    ///
    /// The orchestrator must fetch `default_head` with full ancestry
    /// (no `--depth`) before calling — there is no safe way for the
    /// planner to recover from shallow state without a remote, which
    /// it deliberately does not have.
    #[error(
        "staging repo at {staging_repo} is shallow: `git rev-list --boundary` cannot \
         traverse past the shallow boundary so we cannot tell which bundle commits are \
         new versus already on the default branch. Fetch `default_head` with full ancestry \
         (no `--depth`) — or `git fetch --unshallow` — before calling the planner"
    )]
    ShallowStagingRepo { staging_repo: String },
}

impl From<CleanGitError> for BranchCreationPlanError {
    fn from(err: CleanGitError) -> Self {
        BranchCreationPlanError::Git(err.to_string())
    }
}

/// Result of [`plan_branch_creation_via_rev_list`].
///
/// Two shapes, distinguished by whether the bundle introduces any
/// commits the App side doesn't already have:
///
/// * [`Replay`](BranchCreationPlan::Replay) — the bundle contains
///   genuinely new commits. The orchestrator must run them through
///   [`replay_commits`] before creating the ref on the App side.
/// * [`AlreadyOnDefault`](BranchCreationPlan::AlreadyOnDefault) — the
///   bundle's tip is already reachable from the default branch head
///   (it *is* the default head, or an ancestor of it). The
///   orchestrator can skip replay entirely and create the ref pointing
///   at the existing App-side SHA. This is the "create a branch at
///   `main`" / "create a branch at an older release tag" case: a
///   legitimate push the agent might make even though no objects need
///   uploading.
///
/// Encoding the two shapes as an enum makes the "no replay needed but
/// still publish the ref" case unmissable for the caller; a struct
/// with an `Option<commits>` would let the orchestrator silently
/// forget to create the ref when commits were absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchCreationPlan {
    /// The bundle introduces new commits. `commits` is topologically
    /// sorted (parents before children), suitable as the `commits`
    /// argument to [`replay_commits`]. `seed` is pre-populated with
    /// the boundary commits' identity mappings: each default-side
    /// ancestor that appears as a parent slot of a walked commit maps
    /// to itself, so [`replay_commits`] recognises it as already
    /// published.
    Replay {
        commits: Vec<GitObjectId>,
        seed: ShaMap,
    },
    /// The bundle tip is already reachable from the default branch
    /// head — either equal to it or one of its ancestors. There are
    /// no new commits to upload; the orchestrator only needs to
    /// publish the new ref at `tip` (which is the same SHA on the App
    /// side, since it's already on the default branch).
    AlreadyOnDefault { tip: GitObjectId },
}

/// Plan the per-commit walk for a branch creation by shelling out
/// `git rev-list --topo-order --reverse --boundary ^<default_head>
/// <bundle_tip>` against the staging repo.
///
/// The output of `rev-list --boundary` is exactly what the walker
/// needs:
///
/// * Lines without a leading `-` are interesting commits — those
///   reachable from `bundle_tip` and *not* reachable from
///   `default_head`. With `--topo-order --reverse` they are
///   emitted parents-before-children, ready to feed straight into
///   [`replay_commits`].
/// * Lines with a leading `-` are boundary commits — uninteresting
///   commits (reachable from `default_head`) that are parents of
///   interesting commits. Those SHAs already exist on GitHub under
///   the same SHA, so seeding them in the [`ShaMap`] as identity
///   maps lets `replay_commits` resolve the boundary parents
///   without an upload.
///
/// The success / failure cases the caller has to distinguish:
///
/// * `Ok(`[`BranchCreationPlan::Replay`]`)` — `rev-list` emitted both
///   interesting commits and boundary commits; normal replay.
/// * `Ok(`[`BranchCreationPlan::AlreadyOnDefault`]`)` — `rev-list`
///   emitted nothing, meaning the bundle tip is reachable from the
///   default branch head. Legitimate "create a branch at this
///   existing commit" push; no upload needed.
/// * [`BranchCreationPlanError::ShallowStagingRepo`] — the staging
///   repo's `.git/shallow` file exists, so rev-list cannot see
///   ancestors older than the shallow depth. The orchestrator must
///   fetch full ancestry before calling; see the variant's doc for
///   the failure mode this prevents.
/// * [`BranchCreationPlanError::DisjointHistory`] — `rev-list`
///   emitted interesting commits but no boundary commits. The
///   bundle's history has no ancestor reachable from the default
///   branch.
/// * [`BranchCreationPlanError::Git`] — the `rev-list` invocation
///   itself failed (unknown SHA, missing staging repo, IO error).
///
/// Pre-conditions:
///
/// * `staging_repo` is a bare repository the broker controls and
///   already contains both `bundle_tip` (from unbundling) and
///   `default_head` (the orchestrator must fetch this before
///   calling — it cannot rely on the bundle to include it).
/// * The staging repo is *not* shallow with respect to the default
///   branch: every ancestor of `default_head` reachable from the
///   bundle must be present locally so rev-list can compute the
///   merge-base. The planner checks this before running rev-list and
///   returns [`BranchCreationPlanError::ShallowStagingRepo`] if a
///   `.git/shallow` file exists.
/// * `git_program` is the resolved path to the host's `git` binary;
///   the same value the rest of the replay pipeline uses.
pub async fn plan_branch_creation_via_rev_list(
    bundle_tip: &GitObjectId,
    default_head: &GitObjectId,
    staging_repo: &Path,
    git_program: &Path,
    step_timeout: Duration,
) -> Result<BranchCreationPlan, BranchCreationPlanError> {
    let shallow_invocation = build_is_shallow_invocation(staging_repo, git_program);
    let shallow_stdout =
        clean_git::run_clean_git_capture_stdout(&shallow_invocation, step_timeout, None).await?;
    if parse_is_shallow_output(&shallow_stdout)? {
        return Err(BranchCreationPlanError::ShallowStagingRepo {
            staging_repo: staging_repo.display().to_string(),
        });
    }

    let invocation =
        build_rev_list_boundary_invocation(staging_repo, git_program, bundle_tip, default_head);
    let stdout = clean_git::run_clean_git_capture_stdout(&invocation, step_timeout, None).await?;
    let (commits, boundaries) = parse_rev_list_boundary_output(&stdout)?;

    if commits.is_empty() {
        // `rev-list ^default_head bundle_tip` with no output means
        // `bundle_tip` is reachable from `default_head` — either equal
        // or an ancestor. The orchestrator should publish the ref at
        // the existing App-side SHA without running replay.
        //
        // No boundary commits accompany this case: `--boundary` only
        // emits parents of interesting commits, and there are no
        // interesting commits here.
        return Ok(BranchCreationPlan::AlreadyOnDefault {
            tip: bundle_tip.clone(),
        });
    }
    if boundaries.is_empty() {
        return Err(BranchCreationPlanError::DisjointHistory {
            default_head: default_head.as_str().to_string(),
            bundle_tip: bundle_tip.as_str().to_string(),
        });
    }

    let mut seed = ShaMap::new();
    for boundary in boundaries {
        seed.seed_commit_identity(boundary);
    }

    Ok(BranchCreationPlan::Replay { commits, seed })
}

/// Result of [`plan_fast_forward_via_rev_list`].
///
/// Two shapes, distinguished by whether the bundle introduces any
/// commits the App side doesn't already have:
///
/// * [`Replay`](FastForwardPlan::Replay) — the bundle contains
///   genuinely new commits between `expected_remote_head` and
///   `bundle_tip`. The orchestrator must run them through
///   [`replay_commits`] and then `update_ref` the App-side branch.
/// * [`AlreadyAtExpected`](FastForwardPlan::AlreadyAtExpected) — the
///   bundle's tip equals `expected_remote_head`. A push of an
///   unchanged ref is a no-op for replay; the orchestrator can skip
///   both the walker and the ref-update entirely.
///
/// Encoding the two shapes as an enum makes the noop case unmissable
/// for the caller and parallels [`BranchCreationPlan`] for symmetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FastForwardPlan {
    /// The bundle introduces new commits. `commits` is topologically
    /// sorted (parents before children), suitable as the `commits`
    /// argument to [`replay_commits`]. `seed` is pre-populated with
    /// the boundary commits' identity mappings — for a strict
    /// fast-forward the boundary is `expected_remote_head` itself
    /// (plus any older ancestors that appear as a parent slot of a
    /// merge commit on the new side).
    Replay {
        commits: Vec<GitObjectId>,
        seed: ShaMap,
    },
    /// `bundle_tip` equals `expected_remote_head` — a noop push of an
    /// unchanged ref. The orchestrator only needs to record the audit
    /// outcome; nothing has to land on GitHub.
    AlreadyAtExpected { tip: GitObjectId },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FastForwardPlanError {
    /// The `git rev-list` subprocess itself failed (unknown SHA,
    /// missing staging repo, IO error, exit-status non-zero).
    ///
    /// Stringified rather than carrying the underlying
    /// `CleanGitError` for the same reason
    /// [`BranchCreationPlanError::Git`] does: the clean-git module
    /// is `pub(crate)` and publishing one of its variants here would
    /// force the entire hardening helper out into the public surface.
    #[error("`git rev-list` failed: {0}")]
    Git(String),
    #[error(
        "`git rev-list --boundary` emitted a line that does not parse as a commit SHA: \
         {line:?} ({reason})"
    )]
    InvalidRevListOutput { line: String, reason: String },
    /// The bundle is not a fast-forward of `expected_remote_head`:
    /// `expected_remote_head` is not an ancestor of `bundle_tip`.
    ///
    /// Three shapes collapse to this variant:
    ///
    /// * Orphan / disjoint: `rev-list --boundary
    ///   ^expected_remote_head bundle_tip` emits interesting commits
    ///   but no boundary at all — the two histories share no commits.
    /// * Fork from older ancestor: `rev-list` emits interesting commits
    ///   plus a boundary, but the boundary is an ancestor older than
    ///   `expected_remote_head` (e.g. `c0 → expected` on one side,
    ///   `c0 → bundle_tip` on the other). Detected by checking that
    ///   `expected_remote_head` itself appears among the boundaries.
    /// * Rewind: `bundle_tip` is a strict ancestor of
    ///   `expected_remote_head`. `rev-list ^expected bundle_tip`
    ///   emits nothing because `bundle_tip` is reachable from
    ///   `expected_remote_head`. Distinguished from the noop case
    ///   (`AlreadyAtExpected`) by SHA inequality.
    ///
    /// Either the agent force-pushed, or the bundle was constructed
    /// against a different baseline than the `expected_remote_head`
    /// the staged receipt declares. Refusing here keeps the broker
    /// from publishing a chain that doesn't descend from the branch
    /// tip the agent claimed to be advancing — which is the broker's
    /// correctness contract for fast-forward promotion.
    #[error(
        "bundle history is not a fast-forward of expected_remote_head {expected_remote_head}: \
         {expected_remote_head} is not an ancestor of {bundle_tip}"
    )]
    DivergedHistory {
        expected_remote_head: String,
        bundle_tip: String,
    },
    /// The staging repo is shallow.
    ///
    /// Same failure mode as
    /// [`BranchCreationPlanError::ShallowStagingRepo`]: `rev-list`
    /// cannot traverse past a `.git/shallow` boundary, so the planner
    /// would falsely report the wrong outcome (probably
    /// `DivergedHistory`) if the bundle's fork point is older than the
    /// shallow depth. The orchestrator must fetch
    /// `expected_remote_head` with full ancestry before calling.
    #[error(
        "staging repo at {staging_repo} is shallow: `git rev-list --boundary` cannot \
         traverse past the shallow boundary so we cannot tell which bundle commits are \
         new versus already on expected_remote_head. Fetch `expected_remote_head` with \
         full ancestry (no `--depth`) — or `git fetch --unshallow` — before calling \
         the planner"
    )]
    ShallowStagingRepo { staging_repo: String },
}

impl From<CleanGitError> for FastForwardPlanError {
    fn from(err: CleanGitError) -> Self {
        FastForwardPlanError::Git(err.to_string())
    }
}

/// Plan the per-commit walk for a fast-forward push by shelling out
/// `git rev-list --topo-order --reverse --boundary
/// ^<expected_remote_head> <bundle_tip>` against the staging repo.
///
/// Algorithm-identical to [`plan_branch_creation_via_rev_list`] —
/// they share every private helper — but interprets the rev-list
/// output through the stricter fast-forward lens. A fast-forward
/// push requires that `expected_remote_head` is an ancestor of
/// `bundle_tip`; the planner verifies that explicitly rather than
/// inferring it from rev-list output shape:
///
/// * `bundle_tip == expected_remote_head` → noop, surfaces as
///   [`FastForwardPlan::AlreadyAtExpected`]. Detected before
///   inspecting boundary output: the empty rev-list output also
///   occurs on a rewind (bundle_tip is a strict ancestor of
///   expected_remote_head), so SHA equality is the only reliable
///   noop signal.
/// * `rev-list` emits non-empty `commits` and lists
///   `expected_remote_head` itself among the boundaries → normal
///   replay. The boundary commits seed the `ShaMap` as identity
///   maps so the walker recognises them as already-published
///   parents.
/// * Anything else (empty `commits` with unequal SHAs; non-empty
///   `commits` without `expected_remote_head` among the boundaries)
///   → [`FastForwardPlanError::DivergedHistory`]. This covers
///   rewinds, orphan histories, and forks from an older common
///   ancestor.
///
/// Pre-conditions: same as the branch-creation variant. The staging
/// repo must contain both `bundle_tip` (from unbundling) and
/// `expected_remote_head` (fetched by the orchestrator with full
/// ancestry); the repo must not be shallow.
pub async fn plan_fast_forward_via_rev_list(
    bundle_tip: &GitObjectId,
    expected_remote_head: &GitObjectId,
    staging_repo: &Path,
    git_program: &Path,
    step_timeout: Duration,
) -> Result<FastForwardPlan, FastForwardPlanError> {
    let shallow_invocation = build_is_shallow_invocation(staging_repo, git_program);
    let shallow_stdout =
        clean_git::run_clean_git_capture_stdout(&shallow_invocation, step_timeout, None).await?;
    if parse_is_shallow_output(&shallow_stdout).map_err(branch_creation_to_fast_forward)? {
        return Err(FastForwardPlanError::ShallowStagingRepo {
            staging_repo: staging_repo.display().to_string(),
        });
    }

    let invocation = build_rev_list_boundary_invocation(
        staging_repo,
        git_program,
        bundle_tip,
        expected_remote_head,
    );
    let stdout = clean_git::run_clean_git_capture_stdout(&invocation, step_timeout, None).await?;
    let (commits, boundaries) =
        parse_rev_list_boundary_output(&stdout).map_err(branch_creation_to_fast_forward)?;

    let diverged = || FastForwardPlanError::DivergedHistory {
        expected_remote_head: expected_remote_head.as_str().to_string(),
        bundle_tip: bundle_tip.as_str().to_string(),
    };

    if commits.is_empty() {
        // `rev-list ^expected_remote_head bundle_tip` with no output
        // means `bundle_tip` is reachable from `expected_remote_head`.
        // Two cases collapse onto this: bundle_tip == expected
        // (noop, accept) and bundle_tip is a strict ancestor (rewind,
        // reject). SHA equality is the only reliable discriminator.
        if bundle_tip == expected_remote_head {
            return Ok(FastForwardPlan::AlreadyAtExpected {
                tip: bundle_tip.clone(),
            });
        }
        return Err(diverged());
    }
    // For the walk to be a true fast-forward, `expected_remote_head`
    // itself must be one of the boundaries — i.e. it's reachable
    // from `bundle_tip`. A non-empty boundary list that does *not*
    // contain `expected_remote_head` means the bundle forked from
    // some older common ancestor (which rev-list reports as the
    // boundary) and is therefore divergent.
    if !boundaries.iter().any(|b| b == expected_remote_head) {
        return Err(diverged());
    }

    let mut seed = ShaMap::new();
    for boundary in boundaries {
        seed.seed_commit_identity(boundary);
    }

    Ok(FastForwardPlan::Replay { commits, seed })
}

/// Total adapter from the branch-creation planner's error type to the
/// fast-forward planner's. Used at the boundary where the parse
/// helpers return `BranchCreationPlanError` but the fast-forward
/// orchestration needs `FastForwardPlanError`.
///
/// The parse helpers only ever construct `InvalidRevListOutput` at
/// the time of writing, so the other arms are unreachable in
/// practice. Keeping the function total (rather than
/// `unreachable!`-panicking) means a future refactor that lets the
/// parse helpers emit a different variant translates cleanly into
/// the fast-forward vocabulary rather than crashing the broker.
/// `DisjointHistory` maps to `DivergedHistory` because the two
/// describe the same shape ("no ancestor of bundle_tip on the App
/// side") with different baseline names.
fn branch_creation_to_fast_forward(err: BranchCreationPlanError) -> FastForwardPlanError {
    match err {
        BranchCreationPlanError::Git(msg) => FastForwardPlanError::Git(msg),
        BranchCreationPlanError::InvalidRevListOutput { line, reason } => {
            FastForwardPlanError::InvalidRevListOutput { line, reason }
        }
        BranchCreationPlanError::ShallowStagingRepo { staging_repo } => {
            FastForwardPlanError::ShallowStagingRepo { staging_repo }
        }
        BranchCreationPlanError::DisjointHistory {
            default_head,
            bundle_tip,
        } => FastForwardPlanError::DivergedHistory {
            expected_remote_head: default_head,
            bundle_tip,
        },
    }
}

/// Build the `git -C <staging> rev-parse --is-shallow-repository`
/// invocation: prints `true`/`false` on stdout depending on whether
/// `.git/shallow` exists. Used as the planner's pre-flight check.
///
/// Cheap: no object reads, just a stat on `.git/shallow`.
fn build_is_shallow_invocation(staging_repo: &Path, git_program: &Path) -> CleanGitInvocation {
    CleanGitInvocation::new(
        git_program.to_path_buf(),
        [
            OsString::from("-C"),
            staging_repo.as_os_str().to_os_string(),
            OsString::from("rev-parse"),
            OsString::from("--is-shallow-repository"),
        ],
        clean_git_config_env(),
        Vec::new(),
    )
}

/// Parse `rev-parse --is-shallow-repository` output. Git prints
/// `true` or `false` followed by a newline; anything else is treated
/// as malformed and surfaced via `InvalidRevListOutput` so a future
/// Git change cannot silently regress the precondition.
fn parse_is_shallow_output(stdout: &[u8]) -> Result<bool, BranchCreationPlanError> {
    let text = std::str::from_utf8(stdout).map_err(|err| {
        BranchCreationPlanError::InvalidRevListOutput {
            line: format!("<non-utf8 stdout, {} bytes>", stdout.len()),
            reason: err.to_string(),
        }
    })?;
    match text.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(BranchCreationPlanError::InvalidRevListOutput {
            line: other.to_string(),
            reason: "`git rev-parse --is-shallow-repository` must print `true` or `false`"
                .to_string(),
        }),
    }
}

/// Build the `git -C <staging> rev-list --topo-order --reverse
/// --boundary ^<default_head> <bundle_tip>` invocation under the
/// hardened clean-git environment.
///
/// Pure helper exposed for tests so the argv shape can be pinned
/// without running git.
fn build_rev_list_boundary_invocation(
    staging_repo: &Path,
    git_program: &Path,
    bundle_tip: &GitObjectId,
    default_head: &GitObjectId,
) -> CleanGitInvocation {
    CleanGitInvocation::new(
        git_program.to_path_buf(),
        [
            OsString::from("-C"),
            staging_repo.as_os_str().to_os_string(),
            OsString::from("rev-list"),
            OsString::from("--topo-order"),
            OsString::from("--reverse"),
            OsString::from("--boundary"),
            OsString::from(format!("^{}", default_head.as_str())),
            OsString::from(bundle_tip.as_str()),
        ],
        clean_git_config_env(),
        Vec::new(),
    )
}

/// Parse one `rev-list --boundary` stdout into two SHA buckets:
/// interesting commits (no prefix, in emission order) and boundary
/// commits (lines prefixed with `-`).
///
/// Each non-empty line is exactly one SHA (optionally with a `-`
/// prefix). Anything else — a malformed SHA, a non-ASCII byte — is
/// surfaced as [`BranchCreationPlanError::InvalidRevListOutput`]
/// rather than silently dropped, so a future Git change that adds
/// noise to this output cannot regress to producing a wrong walk.
fn parse_rev_list_boundary_output(
    stdout: &[u8],
) -> Result<(Vec<GitObjectId>, Vec<GitObjectId>), BranchCreationPlanError> {
    let text = std::str::from_utf8(stdout).map_err(|err| {
        BranchCreationPlanError::InvalidRevListOutput {
            line: format!("<non-utf8 stdout, {} bytes>", stdout.len()),
            reason: err.to_string(),
        }
    })?;

    let mut commits: Vec<GitObjectId> = Vec::new();
    let mut boundaries: Vec<GitObjectId> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (is_boundary, sha_str) = match line.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        let sha = GitObjectId::new(sha_str.to_string()).map_err(|err| match err {
            GitObjectIdError::WrongLength(_) | GitObjectIdError::NonHexByte(_) => {
                BranchCreationPlanError::InvalidRevListOutput {
                    line: line.to_string(),
                    reason: err.to_string(),
                }
            }
        })?;
        if is_boundary {
            boundaries.push(sha);
        } else {
            commits.push(sha);
        }
    }
    Ok((commits, boundaries))
}

/// Render the replayed commit message: the original body plus
/// trailers expanded from the supplied [`TrailerSource`] slice.
///
/// Two cases distinguished by inspecting the existing message's
/// final paragraph:
///
/// * If the last paragraph already looks like a trailer block (each
///   line matches `^[A-Za-z][A-Za-z0-9-]*: `), the new trailers are
///   appended to it without an extra blank line, so the result has a
///   single trailer block at the end of the message.
/// * Otherwise, a blank line is inserted and the new trailers form
///   their own block.
///
/// The first case is what `git interpret-trailers --where end` does
/// for `Co-authored-by:` and friends; matching its semantics lets
/// `git interpret-trailers --parse` see *all* trailers on the
/// replayed commit, including those that were already on the bundle
/// commit.
fn render_message(
    original: &str,
    trailers: &[TrailerSource],
    bundle_commit_sha: &GitObjectId,
) -> String {
    if trailers.is_empty() {
        return original.to_string();
    }
    // Normalise the input: strip any number of trailing newlines so
    // we control the join. The original message's intermediate
    // blank lines are preserved.
    let trimmed = original.trim_end_matches('\n');

    let mut new_block = String::new();
    for source in trailers {
        let line = render_trailer_line(source, bundle_commit_sha);
        if !new_block.is_empty() {
            new_block.push('\n');
        }
        new_block.push_str(&line);
    }

    let joiner = if trimmed.is_empty() {
        // Pathological: an empty message gets a trailer-only body.
        // Git accepts this.
        ""
    } else if ends_with_trailer_block(trimmed) {
        "\n"
    } else {
        "\n\n"
    };

    let mut out = String::with_capacity(trimmed.len() + joiner.len() + new_block.len() + 1);
    out.push_str(trimmed);
    out.push_str(joiner);
    out.push_str(&new_block);
    // Restore a single trailing newline — git's own commit objects
    // always end with one, and reviewers comparing replayed messages
    // against bundle ones expect that invariant.
    out.push('\n');
    out
}

fn render_trailer_line(source: &TrailerSource, bundle_commit_sha: &GitObjectId) -> String {
    match source {
        TrailerSource::Fixed { key, value } => format!("{}: {}", key.as_str(), value.as_str()),
        TrailerSource::OriginalCommitSha { key } => {
            format!("{}: {}", key.as_str(), bundle_commit_sha.as_str())
        }
    }
}

/// Does this message end with a paragraph whose every line is a
/// well-formed trailer, *separated from earlier content by a blank
/// line*?
///
/// The blank-line separation matters: `git interpret-trailers` only
/// recognises a trailer block when it is the final paragraph of a
/// message that has more than one paragraph. A single-paragraph
/// message — even one whose subject line happens to match trailer
/// syntax (`Fix: bug`, conventional-commits subjects like
/// `feat: …`) — is treated as the subject only, with no trailer
/// block. If we joined the appended trailer to that subject with a
/// single newline we would produce `Fix: bug\nReplay-from: …` and
/// `git interpret-trailers --parse` would silently drop the
/// provenance trailer, defeating the replay traceability contract.
///
/// We use stricter "every line must match" matching rather than git's
/// 75% heuristic so that a near-trailer block (one prose line
/// followed by trailers) is treated as prose and gets its own
/// blank-line-separated trailer block on output.
fn ends_with_trailer_block(message: &str) -> bool {
    let trimmed = message.trim_end_matches('\n');
    let Some((_, last_paragraph)) = trimmed.rsplit_once("\n\n") else {
        // No blank-line separator: the whole message is one
        // paragraph, which `git interpret-trailers` treats as the
        // subject. Force a new trailer block via the `\n\n` joiner
        // in the caller.
        return false;
    };
    if last_paragraph.is_empty() {
        return false;
    }
    last_paragraph.lines().all(is_trailer_line)
}

fn is_trailer_line(line: &str) -> bool {
    let Some(colon) = line.find(':') else {
        return false;
    };
    let (key, rest) = line.split_at(colon);
    if key.is_empty() {
        return false;
    }
    let mut bytes = key.bytes();
    // Cannot panic: emptiness ruled out above.
    let first = bytes.next().expect("non-empty key");
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for byte in bytes {
        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
    }
    // After the colon must come a space (and then the value, which
    // is unconstrained — git accepts pretty much anything to the
    // right of the colon-space).
    rest.starts_with(": ")
}

// Helpers visible to tests that want to assert against the
// trailer-detection contract without round-tripping through the
// full walker.
#[cfg(test)]
pub(crate) fn message_ends_with_trailer_block(message: &str) -> bool {
    ends_with_trailer_block(message)
}

#[cfg(test)]
pub(crate) fn render_replay_message(
    original: &str,
    trailers: &[TrailerSource],
    bundle_commit_sha: &GitObjectId,
) -> String {
    render_message(original, trailers, bundle_commit_sha)
}

// Exposed for the `InMemoryGitObjectSource` test fixture so
// downstream test modules (later slices) can reuse it. Gated on
// test for now — when the production cat-file source lands, it
// will live alongside this module and the fixture stays test-only.
#[cfg(test)]
pub(crate) mod test_fixture {
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
        async fn read_commit(
            &self,
            sha: &GitObjectId,
        ) -> Result<StagingCommit, GitObjectSourceError> {
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
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use proptest::prelude::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::test_fixture::InMemoryGitObjectSource;
    use super::*;
    use crate::git_push_replay::{TrailerKey, TrailerValue};

    fn sample_repo() -> RepoRef {
        RepoRef::from_str("owner/name").unwrap()
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn sample_identity(name: &str) -> CommitIdentity {
        use time::macros::datetime;
        CommitIdentity::new(
            name,
            format!("{name}@example.invalid"),
            datetime!(2024-01-15 10:30:45 UTC),
        )
        .expect("sample date formats")
    }

    fn client_against(server: &MockServer, token: &str) -> GitDataClient {
        GitDataClient::new(reqwest::Client::new(), server.uri(), token.to_string())
    }

    /// Mount a blob create that strictly matches the given content
    /// and responds with the given SHA. Returns nothing — failing
    /// the strict body match shows up as the test's commit-create
    /// matcher never firing (or wiremock surfaces an unmatched
    /// request).
    async fn mount_blob_create(server: &MockServer, content: &[u8], returned: &GitObjectId) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content);
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .and(body_json(json!({
                "content": encoded,
                "encoding": "base64",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_tree_create(
        server: &MockServer,
        expected_body: serde_json::Value,
        returned: &GitObjectId,
    ) {
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_commit_create(
        server: &MockServer,
        expected_body: serde_json::Value,
        returned: &GitObjectId,
    ) {
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    // ----- render_message tests --------------------------------

    #[test]
    fn render_message_returns_original_when_no_trailers() {
        let bundle = sample_object_id('a');
        let out = render_replay_message("subject\n\nbody\n", &[], &bundle);
        assert_eq!(out, "subject\n\nbody\n");
    }

    #[test]
    fn render_message_appends_fixed_trailer_after_blank_line_when_body_is_prose() {
        let bundle = sample_object_id('a');
        let trailer = TrailerSource::Fixed {
            key: TrailerKey::new("Co-authored-by").unwrap(),
            value: TrailerValue::new("Octocat <octocat@example.invalid>").unwrap(),
        };
        let out = render_replay_message("subject\n\nbody\n", &[trailer], &bundle);
        assert_eq!(
            out,
            "subject\n\nbody\n\nCo-authored-by: Octocat <octocat@example.invalid>\n",
        );
    }

    #[test]
    fn render_message_appends_to_existing_trailer_block_with_single_newline() {
        let bundle = sample_object_id('a');
        let trailer = TrailerSource::Fixed {
            key: TrailerKey::new("Replay-source").unwrap(),
            value: TrailerValue::new("writ-broker").unwrap(),
        };
        let original = "subject\n\nbody\n\nCo-authored-by: Alice <alice@example.invalid>\n";
        let out = render_replay_message(original, &[trailer], &bundle);
        // Single trailer block at the end — no blank line between
        // the existing Co-authored-by and our new Replay-source.
        assert_eq!(
            out,
            "subject\n\nbody\n\nCo-authored-by: Alice <alice@example.invalid>\n\
             Replay-source: writ-broker\n",
        );
    }

    /// Regression test: a single-line subject that happens to match
    /// trailer syntax (e.g. a conventional-commits subject like
    /// `feat: foo`) is the subject, not a trailer block. The new
    /// trailer must be separated by a blank line so
    /// `git interpret-trailers --parse` recognises it.
    #[test]
    fn render_message_treats_trailer_shaped_subject_as_subject_not_trailer_block() {
        let bundle = sample_object_id('a');
        let trailer = TrailerSource::OriginalCommitSha {
            key: TrailerKey::new("Replay-from").unwrap(),
        };
        let out = render_replay_message("Fix: bug\n", &[trailer], &bundle);
        // Blank line between subject and the appended trailer block:
        // git's parser requires this separation, and our walker has
        // to honour it or replayed commits lose their provenance
        // trailer to the parser.
        assert_eq!(
            out,
            format!("Fix: bug\n\nReplay-from: {}\n", bundle.as_str())
        );
    }

    #[test]
    fn trailer_block_detection_rejects_single_paragraph_message() {
        // Even though the line itself matches trailer syntax, with
        // no blank-line separation there is no trailer block to
        // append to — git treats this as a subject.
        assert!(!message_ends_with_trailer_block("Fix: bug\n"));
    }

    #[test]
    fn render_message_substitutes_bundle_sha_in_dynamic_trailer() {
        let bundle = sample_object_id('c');
        let trailer = TrailerSource::OriginalCommitSha {
            key: TrailerKey::new("Replay-from").unwrap(),
        };
        let out = render_replay_message("msg\n", &[trailer], &bundle);
        assert_eq!(out, format!("msg\n\nReplay-from: {}\n", bundle.as_str()),);
    }

    #[test]
    fn render_message_handles_empty_original() {
        let bundle = sample_object_id('a');
        let trailer = TrailerSource::Fixed {
            key: TrailerKey::new("Replay-source").unwrap(),
            value: TrailerValue::new("writ-broker").unwrap(),
        };
        let out = render_replay_message("", &[trailer], &bundle);
        assert_eq!(out, "Replay-source: writ-broker\n");
    }

    #[test]
    fn render_message_strips_redundant_trailing_newlines() {
        let bundle = sample_object_id('a');
        let trailer = TrailerSource::Fixed {
            key: TrailerKey::new("Replay-source").unwrap(),
            value: TrailerValue::new("writ-broker").unwrap(),
        };
        let out = render_replay_message("subject\n\nbody\n\n\n\n", &[trailer], &bundle);
        // The body retains its single trailing newline; the trailer
        // block sits one blank line below it; the whole message
        // ends with exactly one newline.
        assert_eq!(out, "subject\n\nbody\n\nReplay-source: writ-broker\n",);
    }

    #[test]
    fn trailer_block_detection_recognises_well_formed_block() {
        assert!(message_ends_with_trailer_block(
            "subject\n\nCo-authored-by: Alice <a@x>\nSigned-off-by: Bob <b@x>\n",
        ));
    }

    #[test]
    fn trailer_block_detection_rejects_prose_last_paragraph() {
        assert!(!message_ends_with_trailer_block(
            "subject\n\nthis is prose\n"
        ));
    }

    #[test]
    fn trailer_block_detection_rejects_mixed_paragraph() {
        // The last paragraph has one trailer line followed by a
        // prose line. Strict matching: not a trailer block.
        assert!(!message_ends_with_trailer_block(
            "subject\n\nCo-authored-by: Alice <a@x>\nand some prose here\n",
        ));
    }

    // ----- ShaMap tests ----------------------------------------

    #[test]
    fn sha_map_seeds_commit_identity_mapping() {
        let mut map = ShaMap::new();
        let sha = sample_object_id('a');
        map.seed_commit_identity(sha.clone());
        assert_eq!(map.commit(&sha), Some(&sha));
        assert_eq!(map.commit_count(), 1);
        assert_eq!(map.blob_count(), 0);
        assert_eq!(map.tree_count(), 0);
    }

    // ----- walker tests ---------------------------------------

    /// A single bundle commit with no parents, an empty tree, and
    /// no body. Verifies the minimum wire shape end-to-end.
    #[tokio::test]
    async fn replay_uploads_single_initial_commit_with_empty_tree() {
        let server = MockServer::start().await;
        let commit_sha = sample_object_id('1');
        let tree_sha = sample_object_id('2');

        let app_tree_sha = sample_object_id('a');
        let app_commit_sha = sample_object_id('b');

        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(tree_sha.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            commit_sha.clone(),
            StagingCommit {
                tree: tree_sha.clone(),
                parents: vec![],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "initial\n".to_string(),
            },
        );

        mount_tree_create(&server, json!({ "tree": [] }), &app_tree_sha).await;
        mount_commit_create(
            &server,
            json!({
                "message": "initial\n",
                "tree": app_tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Bot",
                    "email": "Bot@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            }),
            &app_commit_sha,
        )
        .await;

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            std::slice::from_ref(&commit_sha),
            ShaMap::new(),
            &[],
        )
        .await
        .expect("walker ok");

        assert_eq!(final_sha, app_commit_sha);
        assert_eq!(map.commit(&commit_sha), Some(&app_commit_sha));
        assert_eq!(map.tree(&tree_sha), Some(&app_tree_sha));
        assert_eq!(map.commit_count(), 1);
        assert_eq!(map.tree_count(), 1);
        assert_eq!(map.blob_count(), 0);
    }

    /// Three commits in a chain: c0 -> c1 -> c2. Each modifies a
    /// single file. Verifies that:
    ///   * the seed commit is not re-uploaded (c0's parent equals
    ///     the seed),
    ///   * each commit's parent in the wire body is the *App-side*
    ///     SHA of the previous commit,
    ///   * the blob and tree maps grow once per new object.
    #[tokio::test]
    async fn replay_walks_linear_chain_and_remaps_parents() {
        let server = MockServer::start().await;
        let upstream = sample_object_id('0');

        let blob_bundle = [sample_object_id('1'), sample_object_id('2')];
        let blob_content: [&[u8]; 2] = [b"alpha\n", b"beta\n"];
        let blob_app = [sample_object_id('a'), sample_object_id('b')];

        let tree_bundle = [sample_object_id('3'), sample_object_id('4')];
        let tree_app = [sample_object_id('c'), sample_object_id('d')];

        let commit_bundle = [sample_object_id('5'), sample_object_id('6')];
        let commit_app = [sample_object_id('e'), sample_object_id('f')];

        let mut source = InMemoryGitObjectSource::new();
        for (i, content) in blob_content.iter().enumerate() {
            source.insert_blob(blob_bundle[i].clone(), content.to_vec());
            mount_blob_create(&server, content, &blob_app[i]).await;
        }

        for (i, tree_sha) in tree_bundle.iter().enumerate() {
            source.insert_tree(
                tree_sha.clone(),
                StagingTree {
                    entries: vec![StagingTreeEntry {
                        path: "file.txt".to_string(),
                        kind: TreeEntryKind::Blob,
                        sha: blob_bundle[i].clone(),
                    }],
                },
            );
            mount_tree_create(
                &server,
                json!({
                    "tree": [{
                        "path": "file.txt",
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_app[i].as_str(),
                    }],
                }),
                &tree_app[i],
            )
            .await;
        }

        let parents_pattern = [vec![upstream.clone()], vec![commit_bundle[0].clone()]];
        let parents_app = [vec![upstream.clone()], vec![commit_app[0].clone()]];
        for (i, commit_sha) in commit_bundle.iter().enumerate() {
            source.insert_commit(
                commit_sha.clone(),
                StagingCommit {
                    tree: tree_bundle[i].clone(),
                    parents: parents_pattern[i].clone(),
                    author: sample_identity("Alice"),
                    committer: sample_identity("Bot"),
                    message: format!("commit {i}\n"),
                },
            );
            let parents_json: Vec<&str> = parents_app[i].iter().map(GitObjectId::as_str).collect();
            mount_commit_create(
                &server,
                json!({
                    "message": format!("commit {i}\n"),
                    "tree": tree_app[i].as_str(),
                    "parents": parents_json,
                    "author": {
                        "name": "Alice",
                        "email": "Alice@example.invalid",
                        "date": "2024-01-15T10:30:45Z",
                    },
                    "committer": {
                        "name": "Bot",
                        "email": "Bot@example.invalid",
                        "date": "2024-01-15T10:30:45Z",
                    },
                }),
                &commit_app[i],
            )
            .await;
        }

        let mut seed = ShaMap::new();
        seed.seed_commit_identity(upstream.clone());

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) =
            replay_commits(&client, &sample_repo(), &source, &commit_bundle, seed, &[])
                .await
                .expect("walker ok");

        assert_eq!(final_sha, commit_app[1]);
        assert_eq!(map.commit_count(), 3); // upstream + 2 replayed
        assert_eq!(map.tree_count(), 2);
        assert_eq!(map.blob_count(), 2);
        // Upstream stays as identity.
        assert_eq!(map.commit(&upstream), Some(&upstream));
    }

    /// A merge commit with two parents, both of which appear earlier
    /// in the topo-sorted list. Verifies that the wire body's
    /// `parents` array preserves order and uses both remapped SHAs.
    #[tokio::test]
    async fn replay_handles_merge_commit_with_two_parents() {
        let server = MockServer::start().await;
        let upstream = sample_object_id('0');

        // Topology:
        //
        //   upstream → c_left
        //            ↘
        //              merge
        //            ↗
        //   upstream → c_right
        let blob_left_bundle = sample_object_id('1');
        let blob_right_bundle = sample_object_id('2');
        let blob_merge_bundle = sample_object_id('3');
        let blob_left_app = sample_object_id('a');
        let blob_right_app = sample_object_id('b');
        let blob_merge_app = sample_object_id('c');

        let tree_left_bundle = sample_object_id('4');
        let tree_right_bundle = sample_object_id('5');
        let tree_merge_bundle = sample_object_id('6');
        let tree_left_app = sample_object_id('d');
        let tree_right_app = sample_object_id('e');
        let tree_merge_app = sample_object_id('f');

        let commit_left_bundle = sample_object_id('7');
        let commit_right_bundle = sample_object_id('8');
        let commit_merge_bundle = sample_object_id('9');
        // Use distinct repeated-nibble SHAs that don't collide with any
        // of the bundle ones above.
        let commit_left_app =
            GitObjectId::new("abababababababababababababababababababab".to_string()).unwrap();
        let commit_right_app =
            GitObjectId::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string()).unwrap();
        let commit_merge_app =
            GitObjectId::new("efefefefefefefefefefefefefefefefefefefef".to_string()).unwrap();

        let mut source = InMemoryGitObjectSource::new();
        source.insert_blob(blob_left_bundle.clone(), b"left\n".to_vec());
        source.insert_blob(blob_right_bundle.clone(), b"right\n".to_vec());
        source.insert_blob(blob_merge_bundle.clone(), b"merged\n".to_vec());
        mount_blob_create(&server, b"left\n", &blob_left_app).await;
        mount_blob_create(&server, b"right\n", &blob_right_app).await;
        mount_blob_create(&server, b"merged\n", &blob_merge_app).await;

        source.insert_tree(
            tree_left_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "f.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: blob_left_bundle.clone(),
                }],
            },
        );
        source.insert_tree(
            tree_right_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "f.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: blob_right_bundle.clone(),
                }],
            },
        );
        source.insert_tree(
            tree_merge_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "f.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: blob_merge_bundle.clone(),
                }],
            },
        );
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "f.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_left_app.as_str(),
                }],
            }),
            &tree_left_app,
        )
        .await;
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "f.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_right_app.as_str(),
                }],
            }),
            &tree_right_app,
        )
        .await;
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "f.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_merge_app.as_str(),
                }],
            }),
            &tree_merge_app,
        )
        .await;

        source.insert_commit(
            commit_left_bundle.clone(),
            StagingCommit {
                tree: tree_left_bundle.clone(),
                parents: vec![upstream.clone()],
                author: sample_identity("L"),
                committer: sample_identity("Bot"),
                message: "left side\n".to_string(),
            },
        );
        source.insert_commit(
            commit_right_bundle.clone(),
            StagingCommit {
                tree: tree_right_bundle.clone(),
                parents: vec![upstream.clone()],
                author: sample_identity("R"),
                committer: sample_identity("Bot"),
                message: "right side\n".to_string(),
            },
        );
        source.insert_commit(
            commit_merge_bundle.clone(),
            StagingCommit {
                tree: tree_merge_bundle.clone(),
                parents: vec![commit_left_bundle.clone(), commit_right_bundle.clone()],
                author: sample_identity("M"),
                committer: sample_identity("Bot"),
                message: "merge\n".to_string(),
            },
        );

        mount_commit_create(
            &server,
            json!({
                "message": "left side\n",
                "tree": tree_left_app.as_str(),
                "parents": [upstream.as_str()],
                "author": { "name": "L", "email": "L@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_left_app,
        )
        .await;
        mount_commit_create(
            &server,
            json!({
                "message": "right side\n",
                "tree": tree_right_app.as_str(),
                "parents": [upstream.as_str()],
                "author": { "name": "R", "email": "R@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_right_app,
        )
        .await;
        mount_commit_create(
            &server,
            json!({
                "message": "merge\n",
                "tree": tree_merge_app.as_str(),
                "parents": [commit_left_app.as_str(), commit_right_app.as_str()],
                "author": { "name": "M", "email": "M@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_merge_app,
        )
        .await;

        let mut seed = ShaMap::new();
        seed.seed_commit_identity(upstream.clone());

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            &[
                commit_left_bundle.clone(),
                commit_right_bundle.clone(),
                commit_merge_bundle.clone(),
            ],
            seed,
            &[],
        )
        .await
        .expect("walker ok");

        assert_eq!(final_sha, commit_merge_app);
        assert_eq!(map.commit_count(), 4); // upstream + left + right + merge
        assert_eq!(map.tree_count(), 3);
        assert_eq!(map.blob_count(), 3);
    }

    /// Two commits share an identical blob via two separate paths.
    /// The blob must be uploaded exactly once and both trees should
    /// reference the same App-side blob SHA.
    #[tokio::test]
    async fn replay_uploads_each_unique_blob_exactly_once() {
        let server = MockServer::start().await;

        let shared_bundle = sample_object_id('1');
        let shared_app = sample_object_id('a');
        let shared_content: &[u8] = b"shared content\n";
        // `.expect(1)` on the mock means a second upload would
        // surface as an unmatched request.
        mount_blob_create(&server, shared_content, &shared_app).await;

        let tree_a_bundle = sample_object_id('2');
        let tree_b_bundle = sample_object_id('3');
        let tree_a_app = sample_object_id('b');
        let tree_b_app = sample_object_id('c');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_blob(shared_bundle.clone(), shared_content.to_vec());
        source.insert_tree(
            tree_a_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "a.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: shared_bundle.clone(),
                }],
            },
        );
        source.insert_tree(
            tree_b_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "b.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: shared_bundle.clone(),
                }],
            },
        );
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "a.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": shared_app.as_str(),
                }],
            }),
            &tree_a_app,
        )
        .await;
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "b.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": shared_app.as_str(),
                }],
            }),
            &tree_b_app,
        )
        .await;

        let commit_a_bundle = sample_object_id('4');
        let commit_b_bundle = sample_object_id('5');
        let commit_a_app = sample_object_id('d');
        let commit_b_app = sample_object_id('e');
        source.insert_commit(
            commit_a_bundle.clone(),
            StagingCommit {
                tree: tree_a_bundle.clone(),
                parents: vec![],
                author: sample_identity("A"),
                committer: sample_identity("Bot"),
                message: "a\n".to_string(),
            },
        );
        source.insert_commit(
            commit_b_bundle.clone(),
            StagingCommit {
                tree: tree_b_bundle.clone(),
                parents: vec![commit_a_bundle.clone()],
                author: sample_identity("B"),
                committer: sample_identity("Bot"),
                message: "b\n".to_string(),
            },
        );
        mount_commit_create(
            &server,
            json!({
                "message": "a\n",
                "tree": tree_a_app.as_str(),
                "parents": [],
                "author": { "name": "A", "email": "A@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_a_app,
        )
        .await;
        mount_commit_create(
            &server,
            json!({
                "message": "b\n",
                "tree": tree_b_app.as_str(),
                "parents": [commit_a_app.as_str()],
                "author": { "name": "B", "email": "B@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_b_app,
        )
        .await;

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            &[commit_a_bundle.clone(), commit_b_bundle.clone()],
            ShaMap::new(),
            &[],
        )
        .await
        .expect("walker ok");

        assert_eq!(final_sha, commit_b_app);
        assert_eq!(map.blob_count(), 1);
        assert_eq!(map.blob(&shared_bundle), Some(&shared_app));
    }

    /// A subtree (sub-directory) inside the root tree. Walker uploads
    /// the subtree first, then the root with the remapped subtree
    /// SHA.
    #[tokio::test]
    async fn replay_walks_nested_subtree_in_post_order() {
        let server = MockServer::start().await;
        let blob_bundle = sample_object_id('1');
        let blob_app = sample_object_id('a');
        mount_blob_create(&server, b"deep\n", &blob_app).await;

        let subtree_bundle = sample_object_id('2');
        let subtree_app = sample_object_id('b');
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "leaf.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_app.as_str(),
                }],
            }),
            &subtree_app,
        )
        .await;

        let root_bundle = sample_object_id('3');
        let root_app = sample_object_id('c');
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "sub",
                    "mode": "040000",
                    "type": "tree",
                    "sha": subtree_app.as_str(),
                }],
            }),
            &root_app,
        )
        .await;

        let commit_bundle = sample_object_id('4');
        let commit_app = sample_object_id('d');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_blob(blob_bundle.clone(), b"deep\n".to_vec());
        source.insert_tree(
            subtree_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "leaf.txt".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: blob_bundle.clone(),
                }],
            },
        );
        source.insert_tree(
            root_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "sub".to_string(),
                    kind: TreeEntryKind::Subtree,
                    sha: subtree_bundle.clone(),
                }],
            },
        );
        source.insert_commit(
            commit_bundle.clone(),
            StagingCommit {
                tree: root_bundle.clone(),
                parents: vec![],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "deep\n".to_string(),
            },
        );

        mount_commit_create(
            &server,
            json!({
                "message": "deep\n",
                "tree": root_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            std::slice::from_ref(&commit_bundle),
            ShaMap::new(),
            &[],
        )
        .await
        .expect("walker ok");

        assert_eq!(final_sha, commit_app);
        assert_eq!(map.tree(&subtree_bundle), Some(&subtree_app));
        assert_eq!(map.tree(&root_bundle), Some(&root_app));
        assert_eq!(map.tree_count(), 2);
    }

    /// The walker appends a `Replay-from` trailer naming the bundle
    /// commit's own SHA. Verified by strict body match against the
    /// commit create endpoint.
    #[tokio::test]
    async fn replay_appends_trailers_to_commit_message() {
        let server = MockServer::start().await;
        let commit_bundle = sample_object_id('1');
        let tree_bundle = sample_object_id('2');
        let tree_app = sample_object_id('a');
        let commit_app = sample_object_id('b');

        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            commit_bundle.clone(),
            StagingCommit {
                tree: tree_bundle.clone(),
                parents: vec![],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "subject\n\nbody\n".to_string(),
            },
        );

        mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

        let expected_message = format!(
            "subject\n\nbody\n\nReplay-from: {}\n",
            commit_bundle.as_str()
        );
        mount_commit_create(
            &server,
            json!({
                "message": expected_message,
                "tree": tree_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

        let trailers = [TrailerSource::OriginalCommitSha {
            key: TrailerKey::new("Replay-from").unwrap(),
        }];
        let client = client_against(&server, "ghs_fake_token");
        let (_, _) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            &[commit_bundle],
            ShaMap::new(),
            &trailers,
        )
        .await
        .expect("walker ok");
    }

    /// A bundle commit names a parent that is in neither the seed
    /// nor the topo-sorted commit list. Walker surfaces this as
    /// [`ReplayError::UnmappedParent`] without silently emitting an
    /// orphan commit.
    #[tokio::test]
    async fn replay_reports_unmapped_parent_without_uploading_commit() {
        let server = MockServer::start().await;
        // The walker is going to read the tree and upload it before
        // it inspects the commit's parents. Mount that one
        // response; if the walker tries to call create_commit
        // anyway, wiremock will surface it as unmatched.
        let commit_bundle = sample_object_id('1');
        let tree_bundle = sample_object_id('2');
        let tree_app = sample_object_id('a');
        let orphan_parent = sample_object_id('9');

        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            commit_bundle.clone(),
            StagingCommit {
                tree: tree_bundle.clone(),
                parents: vec![orphan_parent.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "lone\n".to_string(),
            },
        );
        mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

        let client = client_against(&server, "ghs_fake_token");
        let err = replay_commits(
            &client,
            &sample_repo(),
            &source,
            std::slice::from_ref(&commit_bundle),
            ShaMap::new(),
            &[],
        )
        .await
        .expect_err("unmapped parent must abort the walk");
        match err {
            ReplayError::UnmappedParent {
                bundle_sha,
                parent_sha,
            } => {
                assert_eq!(bundle_sha, commit_bundle.as_str());
                assert_eq!(parent_sha, orphan_parent.as_str());
            }
            other => panic!("expected UnmappedParent, got {other:?}"),
        }
    }

    /// A submodule entry names a commit in a different repository.
    /// The walker must pass the SHA through verbatim — *not* try to
    /// upload it as a commit on the current repo.
    #[tokio::test]
    async fn replay_passes_submodule_commit_sha_through_unchanged() {
        let server = MockServer::start().await;
        // Submodule SHA: not in the in-memory source's commit map.
        // If the walker mistakenly tried to read it, the test would
        // fail with a NotFound source error.
        let submodule_sha = sample_object_id('9');
        let root_bundle = sample_object_id('1');
        let root_app = sample_object_id('a');
        mount_tree_create(
            &server,
            json!({
                "tree": [{
                    "path": "vendored",
                    "mode": "160000",
                    "type": "commit",
                    "sha": submodule_sha.as_str(),
                }],
            }),
            &root_app,
        )
        .await;

        let commit_bundle = sample_object_id('2');
        let commit_app = sample_object_id('b');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(
            root_bundle.clone(),
            StagingTree {
                entries: vec![StagingTreeEntry {
                    path: "vendored".to_string(),
                    kind: TreeEntryKind::Submodule,
                    sha: submodule_sha.clone(),
                }],
            },
        );
        source.insert_commit(
            commit_bundle.clone(),
            StagingCommit {
                tree: root_bundle.clone(),
                parents: vec![],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "vendored\n".to_string(),
            },
        );

        mount_commit_create(
            &server,
            json!({
                "message": "vendored\n",
                "tree": root_app.as_str(),
                "parents": [],
                "author": { "name": "Alice", "email": "Alice@example.invalid", "date": "2024-01-15T10:30:45Z" },
                "committer": { "name": "Bot", "email": "Bot@example.invalid", "date": "2024-01-15T10:30:45Z" },
            }),
            &commit_app,
        )
        .await;

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            std::slice::from_ref(&commit_bundle),
            ShaMap::new(),
            &[],
        )
        .await
        .expect("walker handles submodule entries");

        assert_eq!(final_sha, commit_app);
        // No blob upload happened for the submodule SHA.
        assert_eq!(map.blob_count(), 0);
        // The submodule SHA does not appear in the commit map either
        // — we don't claim to have replayed it on this repo.
        assert_eq!(map.commit(&submodule_sha), None);
    }

    // ----- plan_branch_creation_via_rev_list tests ----------------

    use std::path::PathBuf;
    use std::process::Command;

    /// The planner shell-outs are sub-second under a normal load.
    /// 10s gives plenty of room on a saturated CI host without
    /// letting a wedged child hang the suite indefinitely.
    const TEST_GIT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Assert a planner result is `Replay` and return the inner
    /// `(commits, seed)`. Keeps real-git tests legible without
    /// repeating the `match` boilerplate at every call site.
    fn expect_replay(plan: BranchCreationPlan) -> (Vec<GitObjectId>, ShaMap) {
        match plan {
            BranchCreationPlan::Replay { commits, seed } => (commits, seed),
            BranchCreationPlan::AlreadyOnDefault { tip } => {
                panic!("expected Replay, got AlreadyOnDefault {{ tip: {tip:?} }}")
            }
        }
    }

    fn required_git() -> PathBuf {
        let path = std::env::var_os("PATH")
            .unwrap_or_else(|| panic!("PATH must contain `git` for walker tests"));
        for dir in std::env::split_paths(&path) {
            let candidate = if dir.is_absolute() {
                dir.join("git")
            } else {
                std::env::current_dir().unwrap().join(dir).join("git")
            };
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("`git` not found on PATH for walker tests");
    }

    /// Spawn `git -C <repo> <args>` under the same hardened env the
    /// production planner uses, plus pinned author/committer
    /// identity and date so commit SHAs are deterministic across
    /// runs and machines. Asserts success; returns the full output
    /// for callers that need stdout (e.g. `rev-parse`).
    fn run_git(git: &Path, repo: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new(git)
            .arg("-C")
            .arg(repo)
            .args(args)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .env("HOME", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_AUTHOR_DATE", "2024-01-15T10:30:45Z")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_DATE", "2024-01-15T10:30:45Z")
            .output()
            .unwrap_or_else(|err| panic!("spawning git {args:?} failed: {err}"));
        assert!(
            output.status.success(),
            "git -C {} {args:?} failed with {}: stdout={:?} stderr={}",
            repo.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        output
    }

    fn rev_parse(git: &Path, repo: &Path, rev: &str) -> GitObjectId {
        let out = run_git(git, repo, &["rev-parse", rev]);
        let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
        GitObjectId::new(sha).expect("rev-parse output must be a valid 40-hex SHA")
    }

    /// Fresh tempdir, `git init` inside it, no global config. Returns
    /// `(TempDir, repo_path)` — the caller must keep the TempDir
    /// alive for the test's duration (drop deletes the directory).
    fn init_test_repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        let git = required_git();
        let init = Command::new(&git)
            .args(["init", "--quiet"])
            .arg(&repo)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .env("HOME", "/dev/null")
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&init.stderr),
        );
        (dir, repo, git)
    }

    /// Create an empty commit on HEAD with the given message; return
    /// its SHA. With the pinned env in [`run_git`] the resulting SHA
    /// is deterministic across runs as long as parents are too.
    fn commit_empty(git: &Path, repo: &Path, message: &str) -> GitObjectId {
        run_git(
            git,
            repo,
            &["commit", "--allow-empty", "--quiet", "-m", message],
        );
        rev_parse(git, repo, "HEAD")
    }

    /// Create a merge commit via `commit-tree` with explicit parents.
    /// Uses the tree of the first parent. Returns the merge SHA.
    fn commit_merge(
        git: &Path,
        repo: &Path,
        message: &str,
        parents: &[&GitObjectId],
    ) -> GitObjectId {
        let tree_out = run_git(
            git,
            repo,
            &["rev-parse", &format!("{}^{{tree}}", parents[0].as_str())],
        );
        let tree = String::from_utf8(tree_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        let mut args: Vec<String> = vec![
            "commit-tree".to_string(),
            tree,
            "-m".to_string(),
            message.to_string(),
        ];
        for parent in parents {
            args.push("-p".to_string());
            args.push(parent.as_str().to_string());
        }
        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run_git(git, repo, &args_refs);
        let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
        GitObjectId::new(sha).unwrap()
    }

    // ----- pure helpers --------------------------------------------

    #[test]
    fn build_is_shallow_invocation_pins_argv_shape() {
        let staging = PathBuf::from("/tmp/staging");
        let git = PathBuf::from("/usr/bin/git");
        let invocation = build_is_shallow_invocation(&staging, &git);
        assert_eq!(invocation.program(), git.as_path());
        assert_eq!(
            invocation.display_args_lossy(),
            vec![
                "-C".to_string(),
                "/tmp/staging".to_string(),
                "rev-parse".to_string(),
                "--is-shallow-repository".to_string(),
            ],
        );
        assert!(invocation.required_secret_env().is_empty());
        // Hardened env stays attached to the pre-flight check too —
        // otherwise a malicious `core.fsmonitor` in a parent `.git`
        // dir could fire.
        let names: Vec<&str> = invocation.env().iter().map(|e| e.name()).collect();
        assert!(names.contains(&"GIT_CONFIG_NOSYSTEM"));
        assert!(names.contains(&"HOME"));
    }

    #[test]
    fn parse_is_shallow_output_recognises_true_and_false() {
        assert!(parse_is_shallow_output(b"true\n").unwrap());
        assert!(!parse_is_shallow_output(b"false\n").unwrap());
        // Whitespace tolerance: git always emits a trailing newline,
        // but defensive trim covers windows-CRLF too.
        assert!(parse_is_shallow_output(b"  true  ").unwrap());
        assert!(!parse_is_shallow_output(b"false\r\n").unwrap());
    }

    #[test]
    fn parse_is_shallow_output_rejects_unexpected_value() {
        let err = parse_is_shallow_output(b"maybe\n").unwrap_err();
        match err {
            BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
                assert_eq!(line, "maybe");
            }
            other => panic!("expected InvalidRevListOutput, got {other:?}"),
        }
    }

    #[test]
    fn build_rev_list_boundary_invocation_pins_argv_shape() {
        let staging = PathBuf::from("/tmp/staging");
        let git = PathBuf::from("/usr/bin/git");
        let bundle_tip = sample_object_id('a');
        let default_head = sample_object_id('b');
        let invocation =
            build_rev_list_boundary_invocation(&staging, &git, &bundle_tip, &default_head);
        assert_eq!(invocation.program(), git.as_path());
        assert_eq!(
            invocation.display_args_lossy(),
            vec![
                "-C".to_string(),
                "/tmp/staging".to_string(),
                "rev-list".to_string(),
                "--topo-order".to_string(),
                "--reverse".to_string(),
                "--boundary".to_string(),
                format!("^{}", default_head.as_str()),
                bundle_tip.as_str().to_string(),
            ],
        );
        // Reading the staging repo never needs a credential — the
        // App token is a GitHub-side thing, not a local-git thing.
        assert!(invocation.required_secret_env().is_empty());
        // Sanity-check the hardened-env wiring: the production
        // helper must supply at least the `GIT_CONFIG_NOSYSTEM` and
        // `HOME` entries. Spelling them out here catches regressions
        // where someone swaps out `clean_git_config_env`.
        let names: Vec<&str> = invocation.env().iter().map(|e| e.name()).collect();
        assert!(names.contains(&"GIT_CONFIG_NOSYSTEM"));
        assert!(names.contains(&"HOME"));
    }

    #[test]
    fn parse_rev_list_boundary_output_splits_interesting_and_boundary() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        let stdout = format!("{a}\n{b}\n-{c}\n");
        let (commits, boundaries) = parse_rev_list_boundary_output(stdout.as_bytes()).unwrap();
        let commit_strs: Vec<&str> = commits.iter().map(GitObjectId::as_str).collect();
        let boundary_strs: Vec<&str> = boundaries.iter().map(GitObjectId::as_str).collect();
        assert_eq!(commit_strs, vec![a.as_str(), b.as_str()]);
        assert_eq!(boundary_strs, vec![c.as_str()]);
    }

    #[test]
    fn parse_rev_list_boundary_output_accepts_empty_input() {
        let (commits, boundaries) = parse_rev_list_boundary_output(b"").unwrap();
        assert!(commits.is_empty());
        assert!(boundaries.is_empty());
    }

    #[test]
    fn parse_rev_list_boundary_output_ignores_blank_lines() {
        let sha = "a".repeat(40);
        let stdout = format!("\n{sha}\n\n");
        let (commits, _) = parse_rev_list_boundary_output(stdout.as_bytes()).unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].as_str(), sha);
    }

    #[test]
    fn parse_rev_list_boundary_output_rejects_short_sha() {
        let err = parse_rev_list_boundary_output(b"abc\n").unwrap_err();
        match err {
            BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
                assert_eq!(line, "abc");
            }
            other => panic!("expected InvalidRevListOutput, got {other:?}"),
        }
    }

    #[test]
    fn parse_rev_list_boundary_output_rejects_non_hex_sha() {
        let bad = "z".repeat(40);
        let err = parse_rev_list_boundary_output(bad.as_bytes()).unwrap_err();
        assert!(
            matches!(err, BranchCreationPlanError::InvalidRevListOutput { .. }),
            "got {err:?}",
        );
    }

    #[test]
    fn parse_rev_list_boundary_output_preserves_dash_prefix_in_error_line() {
        // The reported `line` includes the leading `-`, so a future
        // debugger sees exactly what git emitted (boundary or not)
        // rather than an unprefixed snippet that could be mistaken
        // for an interesting commit.
        let err = parse_rev_list_boundary_output(b"-abc\n").unwrap_err();
        match err {
            BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
                assert_eq!(line, "-abc");
            }
            other => panic!("expected InvalidRevListOutput, got {other:?}"),
        }
    }

    #[test]
    fn parse_rev_list_boundary_output_rejects_non_utf8() {
        let mut bytes = vec![b'a'; 40];
        bytes.push(b'\n');
        bytes.push(0xff);
        let err = parse_rev_list_boundary_output(&bytes).unwrap_err();
        match err {
            BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
                assert!(line.contains("non-utf8"), "got {line}");
            }
            other => panic!("expected InvalidRevListOutput, got {other:?}"),
        }
    }

    // ----- real-git end-to-end tests -------------------------------

    #[tokio::test]
    async fn rev_list_plan_returns_single_commit_when_tip_is_child_of_default_head() {
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "default head");
        let c1 = commit_empty(&git, &repo, "one new commit");

        let plan = plan_branch_creation_via_rev_list(&c1, &c0, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay(plan);
        assert_eq!(commits, vec![c1]);
        assert_eq!(seed.commit(&c0), Some(&c0));
        assert_eq!(seed.commit_count(), 1);
    }

    #[tokio::test]
    async fn rev_list_plan_topologically_sorts_linear_chain() {
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "c0");
        let c1 = commit_empty(&git, &repo, "c1");
        let c2 = commit_empty(&git, &repo, "c2");
        let c3 = commit_empty(&git, &repo, "c3");

        let plan = plan_branch_creation_via_rev_list(&c3, &c0, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay(plan);
        assert_eq!(commits, vec![c1.clone(), c2, c3]);
        // `--boundary` reports the merge-base; for a linear chain
        // that's the commit we passed as default_head. The boundary
        // is not c1.
        assert_eq!(seed.commit(&c0), Some(&c0));
        assert!(seed.commit(&c1).is_none());
    }

    #[tokio::test]
    async fn rev_list_plan_handles_merge_with_mixed_age_parents() {
        // Build the topology the in-walker DFS got wrong:
        //
        //   c0 ─ c_old ────────╮
        //    │                 ├─ merge  (bundle tip)
        //    └─ new1 ──────────╯
        //
        // default_head = c_old.  c_old's only ancestor is c0, which
        // is already on default. new1's only ancestor is c0 too, but
        // new1 itself is new. The walker must emit [new1, merge] —
        // never c0 (which is reachable from default_head via c_old).
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "c0");
        let c_old = commit_empty(&git, &repo, "c_old on default");
        // Branch off c0 (older than default head) for the new side.
        run_git(
            &git,
            &repo,
            &["checkout", "--quiet", "-b", "side", c0.as_str()],
        );
        let new1 = commit_empty(&git, &repo, "new1");
        let merge = commit_merge(&git, &repo, "merge", &[&c_old, &new1]);

        let plan = plan_branch_creation_via_rev_list(&merge, &c_old, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay(plan);
        assert_eq!(commits.len(), 2, "got {commits:?}");
        assert!(
            !commits.contains(&c0),
            "c0 must not be uploaded — already on default"
        );
        assert!(
            !commits.contains(&c_old),
            "c_old is default head — must not appear"
        );
        let new1_idx = commits
            .iter()
            .position(|s| s == &new1)
            .expect("new1 emitted");
        let merge_idx = commits
            .iter()
            .position(|s| s == &merge)
            .expect("merge emitted");
        assert!(new1_idx < merge_idx, "new1 must precede merge");
        // The merge-base of merge and c_old is c0; c_old is on the
        // default branch and is also a direct parent of merge, so
        // rev-list reports both as boundaries.
        assert!(
            seed.commit(&c0).is_some() || seed.commit(&c_old).is_some(),
            "expected some default-side ancestor in the seed map, got {seed:?}",
        );
    }

    #[tokio::test]
    async fn rev_list_plan_handles_fork_from_older_default_commit() {
        // c0 ─ c1 ─ c2  (default branch, head = c2)
        //       └─ new   (bundle tip, forked at c1)
        //
        // The DFS approach would walk new → c1 and stop only at c2
        // (never reached); the rev-list approach excludes everything
        // reachable from c2, so c1 (and c0) are out.
        let (_dir, repo, git) = init_test_repo();
        let _c0 = commit_empty(&git, &repo, "c0");
        let c1 = commit_empty(&git, &repo, "c1");
        let c2 = commit_empty(&git, &repo, "c2 (default head)");

        run_git(
            &git,
            &repo,
            &["checkout", "--quiet", "-b", "side", c1.as_str()],
        );
        let new = commit_empty(&git, &repo, "new on side");

        let plan = plan_branch_creation_via_rev_list(&new, &c2, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay(plan);
        assert_eq!(commits, vec![new]);
        // Merge-base is c1, which is the boundary rev-list reports.
        assert_eq!(seed.commit(&c1), Some(&c1));
    }

    #[tokio::test]
    async fn rev_list_plan_rejects_shallow_staging_repo() {
        // Simulate a shallow clone by creating `.git/shallow`. We
        // don't need an actually-truncated history here — the
        // planner's check is "does `.git/shallow` exist", per `git
        // rev-parse --is-shallow-repository`. The variant exists to
        // prevent a real shallow clone from silently masquerading
        // as `DisjointHistory`, so the test pins the detection
        // path, not the underlying truncation behaviour.
        let (_dir, repo, git) = init_test_repo();
        let default_head = commit_empty(&git, &repo, "default");
        let c1 = commit_empty(&git, &repo, "new");

        let shallow_marker = repo.join(".git").join("shallow");
        std::fs::write(&shallow_marker, format!("{}\n", default_head.as_str())).unwrap();
        assert!(shallow_marker.exists(), "marker write must succeed");

        let err =
            plan_branch_creation_via_rev_list(&c1, &default_head, &repo, &git, TEST_GIT_TIMEOUT)
                .await
                .expect_err("shallow staging repo must be rejected");
        match err {
            BranchCreationPlanError::ShallowStagingRepo { staging_repo } => {
                assert_eq!(staging_repo, repo.display().to_string());
            }
            other => panic!("expected ShallowStagingRepo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rev_list_plan_rejects_disjoint_history() {
        let (_dir, repo, git) = init_test_repo();
        let default_head = commit_empty(&git, &repo, "default");
        // Orphan branch: --orphan makes the next commit parentless,
        // so its history shares nothing with `default_head`.
        run_git(&git, &repo, &["checkout", "--quiet", "--orphan", "orphan"]);
        // After --orphan from an empty-tree commit the index is also
        // empty, so an --allow-empty commit produces a parentless
        // empty-tree root.
        let orphan_tip = commit_empty(&git, &repo, "orphan tip");

        let err = plan_branch_creation_via_rev_list(
            &orphan_tip,
            &default_head,
            &repo,
            &git,
            TEST_GIT_TIMEOUT,
        )
        .await
        .expect_err("disjoint history must be rejected");
        match err {
            BranchCreationPlanError::DisjointHistory {
                default_head: dh,
                bundle_tip: bt,
            } => {
                assert_eq!(dh, default_head.as_str());
                assert_eq!(bt, orphan_tip.as_str());
            }
            other => panic!("expected DisjointHistory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rev_list_plan_returns_already_on_default_when_bundle_tip_equals_default_head() {
        // Agent creates a new branch pointing at the current default
        // head (e.g. `git branch feature/foo main && git push origin
        // feature/foo`). No commits to upload — the orchestrator just
        // needs to publish the ref at the existing SHA.
        let (_dir, repo, git) = init_test_repo();
        let head = commit_empty(&git, &repo, "only commit");
        let plan = plan_branch_creation_via_rev_list(&head, &head, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("bundle_tip == default_head must succeed as AlreadyOnDefault");
        match plan {
            BranchCreationPlan::AlreadyOnDefault { tip } => {
                assert_eq!(tip, head);
            }
            other => panic!("expected AlreadyOnDefault, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rev_list_plan_returns_already_on_default_when_bundle_tip_is_ancestor_of_default_head()
    {
        // Agent creates a new branch pointing at an older commit on
        // the default branch (e.g. tagging a past release). No upload
        // needed; the ref publication is still valid.
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "c0");
        let c1 = commit_empty(&git, &repo, "c1 (default head)");

        let plan = plan_branch_creation_via_rev_list(&c0, &c1, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("ancestor bundle_tip must succeed as AlreadyOnDefault");
        match plan {
            BranchCreationPlan::AlreadyOnDefault { tip } => {
                assert_eq!(tip, c0);
            }
            other => panic!("expected AlreadyOnDefault, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rev_list_plan_surfaces_git_error_on_unknown_sha() {
        let (_dir, repo, git) = init_test_repo();
        let head = commit_empty(&git, &repo, "only commit");
        let bogus = GitObjectId::new("0".repeat(40)).unwrap();
        let err = plan_branch_creation_via_rev_list(&bogus, &head, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect_err("unknown SHA must surface as Git error");
        assert!(
            matches!(err, BranchCreationPlanError::Git(_)),
            "expected Git, got {err:?}",
        );
    }

    /// End-to-end integration: feed a real-git plan straight into
    /// `replay_commits` against a wiremock-backed GitHub Git Data
    /// client. Proves the boundary commits land in the seed map in
    /// a shape that satisfies the walker's `UnmappedParent` guard,
    /// without needing an in-memory `GitObjectSource` to mimic
    /// staging-repo topology.
    #[tokio::test]
    async fn rev_list_plan_seeds_replay_commits_end_to_end() {
        let (_dir, repo, git) = init_test_repo();
        let default_head = commit_empty(&git, &repo, "default head");
        let c1 = commit_empty(&git, &repo, "new c1");
        let c2 = commit_empty(&git, &repo, "new c2");

        let plan =
            plan_branch_creation_via_rev_list(&c2, &default_head, &repo, &git, TEST_GIT_TIMEOUT)
                .await
                .expect("plan ok");
        let (plan_commits, plan_seed) = expect_replay(plan);
        assert_eq!(plan_commits, vec![c1.clone(), c2.clone()]);
        assert_eq!(plan_seed.commit(&default_head), Some(&default_head));

        // Stub out blob/tree/commit creation so the replay walker
        // can run without a real GitHub. The bundle commits all
        // share the same empty tree (because both are
        // `commit --allow-empty` on an empty initial repo), so
        // exactly one tree create is expected.
        let server = MockServer::start().await;
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');
        let c2_app = sample_object_id('f');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(json!({ "tree": [] })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c2_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        // In-memory source pre-populated with the two new commits
        // (and the empty tree they share). We don't insert
        // default_head because the seed map identity-maps it; the
        // walker never reads its commit object.
        let mut source = InMemoryGitObjectSource::new();
        let empty_tree_bundle = rev_parse(&git, &repo, &format!("{}^{{tree}}", c1.as_str()));
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle.clone(),
                parents: vec![default_head.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        source.insert_commit(
            c2.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![c1.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c2\n".to_string(),
            },
        );

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            &plan_commits,
            plan_seed,
            &[],
        )
        .await
        .expect("replay ok");

        assert_eq!(final_sha, c2_app);
        assert_eq!(map.commit(&c1), Some(&c1_app));
        assert_eq!(map.commit(&c2), Some(&c2_app));
        assert_eq!(map.commit(&default_head), Some(&default_head));
    }

    // ----- fast-forward planner tests ------------------------------

    /// Same `Replay`-extraction helper as `expect_replay`, but for
    /// the fast-forward result enum. Keeps the per-test asserts focussed
    /// on shape rather than match scaffolding.
    fn expect_replay_ff(plan: FastForwardPlan) -> (Vec<GitObjectId>, ShaMap) {
        match plan {
            FastForwardPlan::Replay { commits, seed } => (commits, seed),
            FastForwardPlan::AlreadyAtExpected { tip } => {
                panic!("expected Replay, got AlreadyAtExpected {{ tip: {tip:?} }}")
            }
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_returns_single_commit_when_tip_is_child_of_expected_remote_head() {
        let (_dir, repo, git) = init_test_repo();
        let expected = commit_empty(&git, &repo, "expected remote head");
        let new1 = commit_empty(&git, &repo, "one new commit");

        let plan = plan_fast_forward_via_rev_list(&new1, &expected, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay_ff(plan);
        assert_eq!(commits, vec![new1]);
        // The boundary is `expected_remote_head` itself — strictly the
        // parent of the only new commit.
        assert_eq!(seed.commit(&expected), Some(&expected));
        assert_eq!(seed.commit_count(), 1);
    }

    #[tokio::test]
    async fn fast_forward_plan_topologically_sorts_linear_chain() {
        let (_dir, repo, git) = init_test_repo();
        let expected = commit_empty(&git, &repo, "expected");
        let c1 = commit_empty(&git, &repo, "c1");
        let c2 = commit_empty(&git, &repo, "c2");
        let c3 = commit_empty(&git, &repo, "c3");

        let plan = plan_fast_forward_via_rev_list(&c3, &expected, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay_ff(plan);
        assert_eq!(commits, vec![c1.clone(), c2, c3]);
        // Boundary is `expected` (the parent of the first new commit
        // on the chain); the new chain's own intermediate commits are
        // not boundaries.
        assert_eq!(seed.commit(&expected), Some(&expected));
        assert!(seed.commit(&c1).is_none());
    }

    #[tokio::test]
    async fn fast_forward_plan_handles_merge_with_mixed_age_parents() {
        // Topology:
        //
        //   c0 ─ expected ─────────╮
        //    │                     ├─ merge  (bundle tip)
        //    └─ side1 ──────────── ╯
        //
        // expected_remote_head = expected.  side1 forks at c0 (older
        // than expected). merge's parents are (expected, side1). The
        // walker must emit [side1, merge], with c0 and/or expected as
        // boundaries so the merge's parent slot resolves.
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "c0");
        let expected = commit_empty(&git, &repo, "expected on default");
        run_git(
            &git,
            &repo,
            &["checkout", "--quiet", "-b", "side", c0.as_str()],
        );
        let side1 = commit_empty(&git, &repo, "side1");
        let merge = commit_merge(&git, &repo, "merge", &[&expected, &side1]);

        let plan = plan_fast_forward_via_rev_list(&merge, &expected, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (commits, seed) = expect_replay_ff(plan);
        assert_eq!(commits.len(), 2, "got {commits:?}");
        assert!(
            !commits.contains(&c0),
            "c0 must not be uploaded — reachable from expected_remote_head"
        );
        assert!(
            !commits.contains(&expected),
            "expected_remote_head must not appear in the upload set"
        );
        let side1_idx = commits
            .iter()
            .position(|s| s == &side1)
            .expect("side1 emitted");
        let merge_idx = commits
            .iter()
            .position(|s| s == &merge)
            .expect("merge emitted");
        assert!(side1_idx < merge_idx, "side1 must precede merge");
        // At least one of {c0, expected} must seed the walker so the
        // merge's parent slot can be resolved.
        assert!(
            seed.commit(&c0).is_some() || seed.commit(&expected).is_some(),
            "expected some ancestor in the seed map, got {seed:?}",
        );
    }

    #[tokio::test]
    async fn fast_forward_plan_returns_already_at_expected_when_bundle_tip_equals_expected_remote_head()
     {
        // Agent pushes an unchanged ref (e.g. `git push origin main`
        // with no local commits ahead). The bundle would be empty;
        // the planner must surface this as AlreadyAtExpected so the
        // orchestrator skips both walker and ref-update.
        let (_dir, repo, git) = init_test_repo();
        let head = commit_empty(&git, &repo, "only commit");
        let plan = plan_fast_forward_via_rev_list(&head, &head, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("bundle_tip == expected_remote_head must succeed as AlreadyAtExpected");
        match plan {
            FastForwardPlan::AlreadyAtExpected { tip } => {
                assert_eq!(tip, head);
            }
            other => panic!("expected AlreadyAtExpected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_rejects_diverged_history() {
        // Build an orphan branch as the bundle tip — its history
        // shares nothing with `expected_remote_head`, so `rev-list`
        // emits all of orphan_tip's ancestry as interesting and no
        // boundary commits. That's the "not a fast forward" shape
        // the broker must refuse to publish.
        let (_dir, repo, git) = init_test_repo();
        let expected = commit_empty(&git, &repo, "expected");
        run_git(&git, &repo, &["checkout", "--quiet", "--orphan", "orphan"]);
        let orphan_tip = commit_empty(&git, &repo, "orphan tip");

        let err =
            plan_fast_forward_via_rev_list(&orphan_tip, &expected, &repo, &git, TEST_GIT_TIMEOUT)
                .await
                .expect_err("diverged history must be rejected");
        match err {
            FastForwardPlanError::DivergedHistory {
                expected_remote_head: erh,
                bundle_tip: bt,
            } => {
                assert_eq!(erh, expected.as_str());
                assert_eq!(bt, orphan_tip.as_str());
            }
            other => panic!("expected DivergedHistory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_rejects_fork_from_older_ancestor() {
        // Topology:
        //
        //   c0 ─ expected         (expected_remote_head)
        //    └─ side_tip          (bundle_tip)
        //
        // bundle_tip and expected_remote_head share an older common
        // ancestor `c0`, but neither is an ancestor of the other —
        // this is *diverged*, not a fast-forward. `git rev-list
        // --boundary ^expected side_tip` emits `side_tip` as
        // interesting and `c0` as the boundary, so the naive
        // "boundaries non-empty → Replay" rule wrongly accepts this.
        // The planner must recognise that `expected_remote_head`
        // itself is not the boundary and reject it.
        let (_dir, repo, git) = init_test_repo();
        let c0 = commit_empty(&git, &repo, "c0 shared ancestor");
        let expected = commit_empty(&git, &repo, "expected on default");
        run_git(
            &git,
            &repo,
            &["checkout", "--quiet", "-b", "side", c0.as_str()],
        );
        let side_tip = commit_empty(&git, &repo, "side tip");

        let err =
            plan_fast_forward_via_rev_list(&side_tip, &expected, &repo, &git, TEST_GIT_TIMEOUT)
                .await
                .expect_err("fork from older ancestor must be rejected");
        match err {
            FastForwardPlanError::DivergedHistory {
                expected_remote_head: erh,
                bundle_tip: bt,
            } => {
                assert_eq!(erh, expected.as_str());
                assert_eq!(bt, side_tip.as_str());
            }
            other => panic!("expected DivergedHistory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_rejects_rewind() {
        // Topology: linear chain c1 ─ c2. Caller asks the planner to
        // treat bundle_tip = c1 against expected_remote_head = c2.
        // That's a rewind: bundle_tip is a strict ancestor of
        // expected_remote_head, not a fast-forward. `git rev-list
        // --boundary ^c2 c1` emits nothing (c1 is reachable from c2),
        // so the naive "empty output → AlreadyAtExpected" rule
        // wrongly accepts it as a noop. The planner must check
        // SHA-equality before declaring noop and reject this as
        // DivergedHistory.
        let (_dir, repo, git) = init_test_repo();
        let c1 = commit_empty(&git, &repo, "c1");
        let c2 = commit_empty(&git, &repo, "c2");

        let err = plan_fast_forward_via_rev_list(&c1, &c2, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect_err("rewind must be rejected");
        match err {
            FastForwardPlanError::DivergedHistory {
                expected_remote_head: erh,
                bundle_tip: bt,
            } => {
                assert_eq!(erh, c2.as_str());
                assert_eq!(bt, c1.as_str());
            }
            other => panic!("expected DivergedHistory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_rejects_shallow_staging_repo() {
        let (_dir, repo, git) = init_test_repo();
        let expected = commit_empty(&git, &repo, "expected");
        let c1 = commit_empty(&git, &repo, "new");

        let shallow_marker = repo.join(".git").join("shallow");
        std::fs::write(&shallow_marker, format!("{}\n", expected.as_str())).unwrap();
        assert!(shallow_marker.exists(), "marker write must succeed");

        let err = plan_fast_forward_via_rev_list(&c1, &expected, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect_err("shallow staging repo must be rejected");
        match err {
            FastForwardPlanError::ShallowStagingRepo { staging_repo } => {
                assert_eq!(staging_repo, repo.display().to_string());
            }
            other => panic!("expected ShallowStagingRepo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fast_forward_plan_surfaces_git_error_on_unknown_sha() {
        let (_dir, repo, git) = init_test_repo();
        let head = commit_empty(&git, &repo, "only commit");
        let bogus = GitObjectId::new("0".repeat(40)).unwrap();
        let err = plan_fast_forward_via_rev_list(&bogus, &head, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect_err("unknown SHA must surface as Git error");
        assert!(
            matches!(err, FastForwardPlanError::Git(_)),
            "expected Git, got {err:?}",
        );
    }

    /// End-to-end integration: feed a real-git fast-forward plan
    /// straight into `replay_commits` against a wiremock-backed
    /// GitHub Git Data client. Proves the boundary
    /// (= expected_remote_head) lands in the seed map in a shape that
    /// satisfies the walker's `UnmappedParent` guard, identical in
    /// structure to the branch-creation end-to-end test but with the
    /// fast-forward planner.
    #[tokio::test]
    async fn fast_forward_plan_seeds_replay_commits_end_to_end() {
        let (_dir, repo, git) = init_test_repo();
        let expected = commit_empty(&git, &repo, "expected remote head");
        let c1 = commit_empty(&git, &repo, "new c1");
        let c2 = commit_empty(&git, &repo, "new c2");

        let plan = plan_fast_forward_via_rev_list(&c2, &expected, &repo, &git, TEST_GIT_TIMEOUT)
            .await
            .expect("plan ok");
        let (plan_commits, plan_seed) = expect_replay_ff(plan);
        assert_eq!(plan_commits, vec![c1.clone(), c2.clone()]);
        assert_eq!(plan_seed.commit(&expected), Some(&expected));

        let server = MockServer::start().await;
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');
        let c2_app = sample_object_id('f');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(json!({ "tree": [] })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c2_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut source = InMemoryGitObjectSource::new();
        let empty_tree_bundle = rev_parse(&git, &repo, &format!("{}^{{tree}}", c1.as_str()));
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle.clone(),
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        source.insert_commit(
            c2.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![c1.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c2\n".to_string(),
            },
        );

        let client = client_against(&server, "ghs_fake_token");
        let (final_sha, map) = replay_commits(
            &client,
            &sample_repo(),
            &source,
            &plan_commits,
            plan_seed,
            &[],
        )
        .await
        .expect("replay ok");

        assert_eq!(final_sha, c2_app);
        assert_eq!(map.commit(&c1), Some(&c1_app));
        assert_eq!(map.commit(&c2), Some(&c2_app));
        assert_eq!(map.commit(&expected), Some(&expected));
    }

    /// `branch_creation_to_fast_forward` is total: every variant of
    /// the source enum maps to a sensible variant of the destination.
    /// Pin the mapping so a future refactor can't silently re-route
    /// (e.g. by changing a variant's name) without updating the
    /// adapter.
    #[test]
    fn branch_creation_to_fast_forward_is_total() {
        assert_eq!(
            branch_creation_to_fast_forward(BranchCreationPlanError::Git("boom".to_string())),
            FastForwardPlanError::Git("boom".to_string()),
        );
        assert_eq!(
            branch_creation_to_fast_forward(BranchCreationPlanError::InvalidRevListOutput {
                line: "bad".to_string(),
                reason: "reason".to_string(),
            }),
            FastForwardPlanError::InvalidRevListOutput {
                line: "bad".to_string(),
                reason: "reason".to_string(),
            },
        );
        assert_eq!(
            branch_creation_to_fast_forward(BranchCreationPlanError::ShallowStagingRepo {
                staging_repo: "/tmp/staging".to_string(),
            }),
            FastForwardPlanError::ShallowStagingRepo {
                staging_repo: "/tmp/staging".to_string(),
            },
        );
        assert_eq!(
            branch_creation_to_fast_forward(BranchCreationPlanError::DisjointHistory {
                default_head: "aaaa".to_string(),
                bundle_tip: "bbbb".to_string(),
            }),
            FastForwardPlanError::DivergedHistory {
                expected_remote_head: "aaaa".to_string(),
                bundle_tip: "bbbb".to_string(),
            },
        );
    }

    // ----- property tests ------------------------------------------

    /// Strategy for one well-formed [`TrailerSource`]. Keys and
    /// values follow the validation rules in [`TrailerKey::new`] and
    /// [`TrailerValue::new`]; the `prop_oneof` covers both shapes the
    /// production type admits.
    fn arb_trailer_source() -> impl Strategy<Value = TrailerSource> {
        let key = "[A-Za-z][A-Za-z0-9-]{0,15}"
            .prop_map(|raw| TrailerKey::new(raw).expect("strategy produces valid keys"));
        let value = ".{1,32}".prop_filter_map("contains control bytes", |s| {
            if s.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
                None
            } else {
                Some(TrailerValue::new(s).expect("strategy produces valid values"))
            }
        });
        prop_oneof![
            (key.clone(), value).prop_map(|(key, value)| TrailerSource::Fixed { key, value }),
            key.prop_map(|key| TrailerSource::OriginalCommitSha { key }),
        ]
    }

    /// Strategy for an arbitrary commit message. `(?s)` makes `.`
    /// match newlines so the generator can reach the multi-paragraph
    /// cases the trailer-block detection depends on.
    fn arb_message() -> impl Strategy<Value = String> {
        "(?s).{0,200}"
    }

    /// Create an executable file at `dir/name` containing `body`,
    /// chmod 0o755. Returns the absolute path. Used to inject a
    /// shell-script stand-in for `git` into the planner so we can
    /// exercise failure paths (timeout) without a real git
    /// subprocess.
    fn write_executable_probe(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("probe file create");
        file.write_all(body.as_bytes()).expect("probe body write");
        drop(file);
        let mut perms = std::fs::metadata(&path).expect("probe stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("probe chmod");
        path
    }

    /// Locate an executable on the test runner's `PATH` without
    /// resolving symlinks. Mirrors `resolve_program_for_clean_env` but
    /// returns the caller-visible path so the basename survives into
    /// `argv[0]` after `execve` — required on Nix where coreutils is
    /// a multi-call binary dispatched by `basename(argv[0])`.
    fn locate_on_path(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::var_os("PATH").expect("PATH must be set in tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            match std::fs::metadata(&candidate) {
                Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 => {
                    return candidate;
                }
                _ => {}
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    /// Shell-quote a path so it embeds safely inside a script body.
    fn shell_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let mut quoted = String::with_capacity(raw.len() + 2);
        quoted.push('\'');
        for ch in raw.chars() {
            if ch == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(ch);
            }
        }
        quoted.push('\'');
        quoted
    }

    proptest! {
        /// Without any trailers, [`render_message`] is the identity
        /// on its input. The walker must never mutate a commit
        /// message that it has nothing to append to it.
        #[test]
        fn render_message_with_no_trailers_returns_original(original in arb_message()) {
            let sha = sample_object_id('a');
            prop_assert_eq!(render_replay_message(&original, &[], &sha), original);
        }

        /// When at least one trailer is appended, the rendered
        /// trailer lines appear at the tail of the output in the
        /// same order they were supplied — and the output always
        /// ends with exactly one newline.
        #[test]
        fn render_message_emits_trailers_in_order_at_the_tail(
            original in arb_message(),
            trailers in proptest::collection::vec(arb_trailer_source(), 1..=5),
        ) {
            let sha = sample_object_id('b');
            let out = render_replay_message(&original, &trailers, &sha);
            let trimmed = out.trim_end_matches('\n');
            let lines: Vec<&str> = trimmed.lines().collect();
            let n = trailers.len();
            prop_assert!(lines.len() >= n, "rendered {out:?} too short for {n} trailers");
            let tail = &lines[lines.len() - n..];
            for (idx, source) in trailers.iter().enumerate() {
                let expected = match source {
                    TrailerSource::Fixed { key, value } => {
                        format!("{}: {}", key.as_str(), value.as_str())
                    }
                    TrailerSource::OriginalCommitSha { key } => {
                        format!("{}: {}", key.as_str(), sha.as_str())
                    }
                };
                prop_assert_eq!(tail[idx], &expected, "tail line {} mismatch", idx);
            }
            prop_assert!(out.ends_with('\n'), "rendered {out:?} must end with one newline");
            prop_assert!(
                !out.ends_with("\n\n"),
                "rendered {out:?} must not end with multiple newlines",
            );
        }

        /// When the original message has any non-newline content and
        /// we appended at least one trailer, the rendered output is
        /// recognised by [`ends_with_trailer_block`]. That is the
        /// precondition `git interpret-trailers --parse` needs in
        /// order to pick the appended trailers up at all — failing
        /// it would silently strip the replay provenance trailer.
        #[test]
        fn render_message_output_ends_with_trailer_block_when_original_nonempty(
            original in arb_message().prop_filter(
                "non-newline content required",
                |s| !s.trim_end_matches('\n').is_empty(),
            ),
            trailers in proptest::collection::vec(arb_trailer_source(), 1..=5),
        ) {
            let sha = sample_object_id('c');
            let out = render_replay_message(&original, &trailers, &sha);
            prop_assert!(
                message_ends_with_trailer_block(&out),
                "rendered {out:?} must end with a trailer block",
            );
        }
    }

    proptest! {
        // Real-git tests are slow (subprocess per commit); a small
        // case count covers the chain-length combinatorics without
        // blowing out CI wall time.
        #![proptest_config(ProptestConfig::with_cases(6))]

        /// Any two arbitrary chains with no shared ancestor produce
        /// [`BranchCreationPlanError::DisjointHistory`]; the planner
        /// never silently accepts a bundle whose history shares
        /// nothing with the default branch, regardless of either
        /// chain's depth.
        #[test]
        fn rev_list_plan_rejects_any_disjoint_history(
            default_chain_len in 1u32..=4,
            bundle_chain_len in 1u32..=4,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (_dir, repo, git) = init_test_repo();
            let mut default_tip = commit_empty(&git, &repo, "default 0");
            for i in 1..default_chain_len {
                default_tip = commit_empty(&git, &repo, &format!("default {i}"));
            }
            run_git(&git, &repo, &["checkout", "--quiet", "--orphan", "orphan"]);
            let mut bundle_tip = commit_empty(&git, &repo, "orphan 0");
            for i in 1..bundle_chain_len {
                bundle_tip = commit_empty(&git, &repo, &format!("orphan {i}"));
            }
            let result = rt.block_on(plan_branch_creation_via_rev_list(
                &bundle_tip,
                &default_tip,
                &repo,
                &git,
                TEST_GIT_TIMEOUT,
            ));
            match result {
                Err(BranchCreationPlanError::DisjointHistory {
                    default_head,
                    bundle_tip: bt,
                }) => {
                    prop_assert_eq!(default_head, default_tip.as_str());
                    prop_assert_eq!(bt, bundle_tip.as_str());
                }
                other => prop_assert!(false, "expected DisjointHistory, got {:?}", other),
            }
        }
    }

    /// When the rev-list subprocess does not exit before the
    /// configured timeout, the planner surfaces it as
    /// `Git("...timed out...")` rather than blocking the orchestrator
    /// thread. The probe is a shell script standing in for `git` that
    /// answers the `rev-parse --is-shallow-repository` preflight
    /// cleanly (so the planner reaches `rev-list`) and then stalls.
    ///
    /// `clean_git` strips `PATH` from the child, so the script cannot
    /// resolve `sleep` at exec time. We resolve it from the test
    /// runner's `PATH` (without canonicalising — coreutils is a
    /// multi-call binary on Nix) and embed the path directly so the
    /// stall survives in the cleared environment.
    #[tokio::test]
    async fn plan_branch_creation_surfaces_timeout_when_subprocess_stalls() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().to_path_buf();
        let sleep_bin = locate_on_path("sleep");
        // argv layout under the planner: `-C <staging> <subcommand> ...`.
        // After `shift 2`, `$1` is the git subcommand.
        let script = format!(
            "#!/bin/sh\nshift 2\nif [ \"$1\" = rev-parse ]; then\n  echo false\n  exit 0\nfi\nexec {sleep} 5\n",
            sleep = shell_quote(&sleep_bin),
        );
        let probe = write_executable_probe(dir.path(), "git-sleep", &script);
        let bundle_tip = sample_object_id('a');
        let default_head = sample_object_id('b');
        let short_timeout = Duration::from_millis(150);
        let err = plan_branch_creation_via_rev_list(
            &bundle_tip,
            &default_head,
            &staging,
            &probe,
            short_timeout,
        )
        .await
        .expect_err("sleeping probe must time out");
        match err {
            BranchCreationPlanError::Git(msg) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout indication in error, got: {msg}",
                );
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }
}
