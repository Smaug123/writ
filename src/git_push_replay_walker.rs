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
//! `git cat-file --batch` lands in a later commit, alongside the
//! topology-discovery step that produces the caller's commit list.
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

use crate::core::RepoRef;
use crate::git_push_replay::TrailerSource;
use crate::github_git_db::{
    CommitIdentity, CommitRequest, GitDataClient, GitDataError, TreeEntry, TreeEntryKind,
};
use crate::vm_git::GitObjectId;

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
}
