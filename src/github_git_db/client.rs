//! The GitHub git-data HTTP client.
//!
//! [`GitDataClient`](super::GitDataClient) is the low-level REST wrapper the
//! push pipeline uses to create blobs/trees/commits and read/update refs under
//! the App identity. This module holds only the client's request methods (an
//! inherent `impl` block); the struct, its timeouts/error types, the domain
//! types it returns (`TreeEntry`, `CommitIdentity`, …), and the on-the-wire
//! serialization DTOs stay in the parent module. Split out of
//! `github_git_db.rs` to keep that file readable; behaviour is unchanged.

use super::*;

impl GitDataClient {
    /// `api_base` is the GitHub REST API root *without* a trailing slash
    /// (e.g. `https://api.github.com`); the path segments for each
    /// endpoint are concatenated on. Tests pass a `wiremock` server URI
    /// in to swap the destination.
    ///
    /// Taking [`GitDataTimeouts`] rather than a prebuilt
    /// `reqwest::Client` makes "every Git Data client is bounded" a
    /// fact of the constructor instead of a convention: there is no
    /// way to build one over an unbounded transport.
    pub fn new(
        timeouts: GitDataTimeouts,
        api_base: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            http: git_data_http_client(timeouts),
            small_call: timeouts.small_call,
            api_base: api_base.into(),
            token: token.into(),
        }
    }

    /// `POST /repos/{owner}/{repo}/git/blobs` — upload raw bytes as a
    /// blob and return the SHA GitHub computed for it.
    ///
    /// The body is always sent with `encoding: "base64"`; UTF-8 mode
    /// would let GitHub interpret a CR / LF / NUL byte differently
    /// from the staging repo's view of the same blob, which would
    /// silently desync the SHA the walker is about to plug into the
    /// next tree. Base64 is the unambiguous transport for arbitrary
    /// bytes.
    ///
    /// The returned SHA is what the next tree-create call must use as
    /// the `sha` for the corresponding entry; callers track the
    /// `bundle blob SHA → app blob SHA` mapping themselves.
    pub async fn create_blob(
        &self,
        repo: &RepoRef,
        content: &[u8],
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/blobs",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = BlobCreateBody {
            content: BASE64_STANDARD.encode(content),
            encoding: "base64",
        };
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            // No `small_call` override here — deliberately. This is the
            // one request whose body can be huge (up to the staging
            // repo's 256 MiB per-object ceiling, base64-expanded), and
            // GitHub sends no response bytes until it has consumed the
            // upload, so any bound shorter than a slow uplink needs
            // would kill a legitimately progressing push. The
            // client-level `total` ceiling is what bounds it.
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: BlobCreateResponse = response.json().await?;
        Ok(parsed.sha)
    }

    /// `POST /repos/{owner}/{repo}/git/trees` — create a tree from a
    /// list of entries and return the SHA GitHub assigned.
    ///
    /// The body lists each entry's `path`, `mode`, `type`, and the
    /// SHA of the object it references (a blob, an already-created
    /// subtree, or a submodule commit). We do not use the API's
    /// `base_tree` parameter: the replay walker recursively creates
    /// the trees it needs and points unchanged subtrees at their
    /// existing SHAs, which is unambiguous without a base.
    ///
    /// An empty `entries` slice produces git's well-known empty
    /// tree; the API accepts this and the walker depends on it for
    /// initial commits whose root is empty.
    pub async fn create_tree(
        &self,
        repo: &RepoRef,
        entries: &[TreeEntry],
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/trees",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = TreeCreateBody {
            tree: entries
                .iter()
                .map(|entry| TreeEntryWire {
                    path: &entry.path,
                    mode: entry.kind.mode(),
                    object_type: entry.kind.object_type(),
                    sha: &entry.sha,
                })
                .collect(),
        };
        let response = self
            .http
            .post(&url)
            // No `small_call` override: like `create_blob`, this is an
            // object upload whose body scales with repo content (one
            // wire entry per tree row), so it runs under the
            // client-level `total` ceiling.
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: TreeCreateResponse = response.json().await?;
        Ok(parsed.sha)
    }

    /// `POST /repos/{owner}/{repo}/git/commits` — create a commit
    /// pointing at the given `tree`, with the given `parents`, and
    /// return the SHA GitHub assigned.
    ///
    /// `parents` may be empty for an initial commit, or hold several
    /// entries for an octopus merge. `author` typically preserves
    /// the bundle commit's authorship; `committer` is the App
    /// identity.
    ///
    /// **GitHub does not auto-sign commits created via the Git
    /// Database API**, even when the committer matches the App
    /// identity — that auto-signing only applies to the higher-level
    /// Contents API. If `signature` is `None`, the resulting commit
    /// publishes with `verification.reason = "unsigned"` and no
    /// Verified badge. To get Verified, the caller must supply a
    /// detached PGP/SSH signature over the canonical commit object
    /// here; producing that signature is the replay walker's
    /// responsibility, not this client's.
    ///
    /// `message` is forwarded verbatim — the replay layer is
    /// responsible for appending its provenance trailer before this
    /// is called.
    ///
    /// **When `signature` is `Some`, a returned SHA is a commit GitHub
    /// affirmed as Verified.** GitHub re-canonicalises the wire fields
    /// and checks the signature against the commit object it actually
    /// assembled, then reports the outcome in the response's
    /// `verification` block; a 2xx alone says only "commit created",
    /// not "signature verified". This method therefore reads that
    /// verdict back and refuses to hand out the SHA unless it is
    /// affirmative — see [`GitDataError::UnverifiedSignedCommit`] and
    /// [`GitDataError::MissingVerification`]. Callers can rely on the
    /// stronger statement, which is what lets the replay walker's
    /// output go straight to branch publication.
    ///
    /// When `signature` is `None` no such claim was made, so whatever
    /// verdict GitHub returns (`verified: false, reason: "unsigned"`)
    /// is expected and ignored.
    pub async fn create_commit(
        &self,
        repo: &RepoRef,
        request: &CommitRequest<'_>,
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/commits",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = CommitCreateBody {
            message: request.message,
            tree: request.tree,
            parents: request.parents,
            author: identity_wire(request.author),
            committer: identity_wire(request.committer),
            signature: request.signature,
        };
        let response = self
            .http
            .post(&url)
            // No `small_call` override: a commit object's body is
            // dominated by its message, which the staging repo admits
            // at up to its 256 MiB per-object ceiling and which is
            // forwarded here verbatim. Like the blob upload, this runs
            // under the client-level `total` ceiling.
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: CommitCreateResponse = response.json().await?;
        if request.signature.is_some() {
            match parsed.verification {
                Some(CommitVerification { verified: true, .. }) => {}
                Some(CommitVerification {
                    verified: false,
                    reason,
                }) => {
                    return Err(GitDataError::UnverifiedSignedCommit {
                        sha: parsed.sha.as_str().to_string(),
                        reason: reason.unwrap_or_else(|| "<no reason given>".to_string()),
                    });
                }
                None => {
                    return Err(GitDataError::MissingVerification {
                        sha: parsed.sha.as_str().to_string(),
                    });
                }
            }
        }
        Ok(parsed.sha)
    }

    /// `GET /repos/{owner}/{repo}` — fetch repository metadata and
    /// return the App-side default branch name.
    ///
    /// The replay walker needs this for the branch-creation case: when
    /// the agent's bundle does not name an `expected_remote_head` (the
    /// branch does not yet exist on GitHub), the walker still has to
    /// find a boundary commit that delimits which bundle commits are
    /// new. The default branch's tip is that boundary, and this method
    /// is the first hop in resolving it.
    ///
    /// The repo metadata response carries many fields; only
    /// `default_branch` is exposed. Validation happens at the
    /// boundary: a name GitHub returns that fails [`GitBranchName::new`]
    /// surfaces as [`GitDataError::InvalidDefaultBranch`] rather than
    /// being silently coerced.
    pub async fn get_default_branch(&self, repo: &RepoRef) -> Result<GitBranchName, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let response = self
            .http
            .get(&url)
            .timeout(self.small_call)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: RepoMetadataResponse = response.json().await?;
        GitBranchName::new(parsed.default_branch)
            .map_err(|source| GitDataError::InvalidDefaultBranch { source })
    }

    /// `GET /repos/{owner}/{repo}/git/ref/heads/{branch}` — return
    /// the App-side commit SHA the named branch currently points at.
    ///
    /// Branches in GitHub always point at commits; if the response
    /// indicates a non-commit object the call returns
    /// [`GitDataError::UnexpectedRefObjectType`] rather than handing
    /// back a SHA that the walker would plug into a commit's
    /// `parents` slot.
    ///
    /// The branch name is percent-encoded for the URL path before
    /// interpolation. Git's branch-naming rules permit several
    /// URL-reserved bytes (`#`, `%`, `(`, …) that
    /// [`GitBranchName`] also accepts, so a name like `release#1` or
    /// `100%` would otherwise turn into a URL fragment or a half-built
    /// percent-escape and 404 against GitHub. The hierarchical
    /// separator `/` is preserved so `feature/foo` produces the
    /// expected nested ref path.
    pub async fn get_branch_head(
        &self,
        repo: &RepoRef,
        branch: &GitBranchName,
    ) -> Result<GitObjectId, GitDataError> {
        let encoded_branch = percent_encode_ref_segment(branch.as_str());
        let url = format!(
            "{}/repos/{}/{}/git/ref/heads/{}",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
            encoded_branch,
        );
        let response = self
            .http
            .get(&url)
            .timeout(self.small_call)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: GetRefResponse = response.json().await?;
        if parsed.object.object_type != "commit" {
            return Err(GitDataError::UnexpectedRefObjectType {
                ref_name: format!("refs/heads/{}", branch.as_str()),
                object_type: parsed.object.object_type,
            });
        }
        Ok(parsed.object.sha)
    }

    /// `PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}` —
    /// fast-forward the named branch to `new_head`.
    ///
    /// `force` is hard-coded to `false` at this layer rather than
    /// exposed as a parameter. The broker's promote workflow only
    /// ever publishes an App-identity commit chain that the walker
    /// built from the App-side branch tip the workflow itself looked
    /// up, so a non-fast-forward update would mean the walker
    /// produced a chain that does not descend from the branch tip we
    /// started from — a broker invariant violation rather than a
    /// thing to paper over with a force flag. A 422 from GitHub (the
    /// "not a fast forward" status code) therefore surfaces as a
    /// regular `ApiError` so the operator sees it.
    ///
    /// The endpoint path uses the plural `refs` (vs. the singular
    /// `ref` used by `GET`). This is the actual GitHub URL grammar,
    /// not a typo; the per-method asymmetry is documented at
    /// <https://docs.github.com/en/rest/git/refs>.
    ///
    /// Returns `Ok(())` on a 2xx from GitHub. The 200 response carries
    /// the ref object, but the SHA in it is what we just sent —
    /// comparing it adds no information that the status code did not
    /// already convey.
    pub async fn update_ref(
        &self,
        repo: &RepoRef,
        branch: &GitBranchName,
        new_head: &GitObjectId,
    ) -> Result<(), GitDataError> {
        let encoded_branch = percent_encode_ref_segment(branch.as_str());
        let url = format!(
            "{}/repos/{}/{}/git/refs/heads/{}",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
            encoded_branch,
        );
        let body = UpdateRefBody {
            sha: new_head,
            force: false,
        };
        let response = self
            .http
            .patch(&url)
            .timeout(self.small_call)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        Ok(())
    }
}
