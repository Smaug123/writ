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
//! Signing (the detached SSH signature that drives GitHub's Verified
//! badge) is produced inline when [`replay_commits`] is called with
//! `signing_key: Some(...)`. The walker builds a
//! [`crate::git_commit_sign::CommitSigningInput`] from the same fields
//! it sends in [`crate::github_git_db::CommitRequest`] — same tree,
//! same parents, same author, same committer, same rendered message —
//! and the resulting [`crate::core::SshSignature`] goes in the
//! request's `signature` field. Because GitHub re-canonicalises the
//! wire fields into the same byte form
//! [`crate::git_commit_sign::canonical_commit_bytes`] produces, the
//! signature verifies against the commit GitHub assembles and the
//! published commit's `verification.verified` flag is true.
//!
//! Callers that do not want signed commits (test fixtures, the
//! pre-promote bring-up flows) pass `None` and the request goes out
//! with `signature: None`, matching the pre-B1d behaviour exactly.
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
use crate::core::{RepoRef, SshSignature};
use crate::git_commit_sign::{CommitSignError, CommitSigningInput, sign_commit_for_github};
use crate::git_push_replay::TrailerSource;
use crate::github_git_db::{
    CommitIdentity, CommitRequest, GitDataClient, GitDataError, TreeEntry, TreeEntryKind,
};
use crate::signing::WritSigningKey;
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
    /// Signing the canonical bytes of a commit that the walker
    /// already built failed. Surfaces only when `replay_commits` was
    /// called with `signing_key: Some(...)`. `bundle_sha` is the
    /// staging-repo SHA of the commit whose signature failed so the
    /// caller can correlate the failure with the agent's bundle.
    ///
    /// All three [`CommitSignError`] variants indicate bugs (a
    /// [`CommitIdentity`] that bypassed validation, an `ssh-key`
    /// crate failure, or an SSHSIG armorer that produced output the
    /// wire-validation regex rejects) — none should occur with input
    /// the walker itself constructs. The variant exists so the
    /// failure surfaces with context rather than panicking.
    #[error("signing replayed commit {bundle_sha} failed: {source}")]
    Sign {
        bundle_sha: String,
        #[source]
        source: CommitSignError,
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
///
/// `signing_key` controls whether each replayed commit is published
/// with a detached SSH signature in its `signature` field. `Some(key)`
/// signs every commit in the chain (so GitHub publishes them with
/// `verification.verified == true`); `None` sends each commit
/// unsigned, the original behaviour. The same key is reused for every
/// commit in the walk — signing different commits with different keys
/// in a single walk is not supported.
pub async fn replay_commits<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    commits: &[GitObjectId],
    seed: ShaMap,
    trailers: &[TrailerSource],
    signing_key: Option<&WritSigningKey>,
) -> Result<(GitObjectId, ShaMap), ReplayError> {
    let mut map = seed;
    let mut last_app_sha: Option<GitObjectId> = None;
    for bundle_sha in commits {
        let app_sha = replay_one_commit(
            client,
            repo,
            source,
            &mut map,
            bundle_sha,
            trailers,
            signing_key,
        )
        .await?;
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
///
/// When `signing_key` is `Some`, the canonical bytes of the
/// already-built `CommitRequest` are signed and the resulting
/// `SshSignature` is attached to the same request. The
/// [`CommitSigningInput`] is built from the exact same fields the
/// request carries (root App-side tree, App-side parents in order,
/// author, committer, and the trailer-rendered message), so the
/// signature matches the commit GitHub reassembles from the wire.
async fn replay_one_commit<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    source: &S,
    map: &mut ShaMap,
    bundle_sha: &GitObjectId,
    trailers: &[TrailerSource],
    signing_key: Option<&WritSigningKey>,
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
    let signature: Option<SshSignature> = match signing_key {
        Some(key) => {
            let input = CommitSigningInput {
                tree: &root_app_sha,
                parents: &parents,
                author: &commit.author,
                committer: &commit.committer,
                message: &message,
            };
            Some(
                sign_commit_for_github(key, &input).map_err(|source| ReplayError::Sign {
                    bundle_sha: bundle_sha.as_str().to_string(),
                    source,
                })?,
            )
        }
        None => None,
    };
    let request = CommitRequest {
        tree: &root_app_sha,
        parents: &parents,
        message: &message,
        author: &commit.author,
        committer: &commit.committer,
        signature: signature.as_ref().map(SshSignature::as_str),
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

#[cfg(test)]
mod branch_creation_plan_tests;
#[cfg(test)]
mod fast_forward_plan_tests;
#[cfg(test)]
mod render_message_tests;
#[cfg(test)]
mod signing_tests;
#[cfg(test)]
pub(crate) mod test_fixture;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod walker_tests;

/// Property spec living next to the production code: it states the
/// rendering and disjoint-history contracts over *arbitrary* inputs,
/// where the sibling `*_tests` modules pin individual examples.
#[cfg(test)]
mod spec {
    use super::test_support::*;
    use super::*;
    use crate::git_push_replay::{TrailerKey, TrailerValue};
    use proptest::prelude::*;

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
}
