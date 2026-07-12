//! GitHub Git Database REST client used by the broker's push-replay engine.
//!
//! Replay re-creates every commit between the upstream branch tip and a
//! VM-supplied bundle tip via the GitHub `git/blobs`, `git/trees`, and
//! `git/commits` endpoints under the host App's identity, so the published
//! commits land with the Verified badge while preserving provenance back
//! to the bundle. This module exposes typed wrappers for those endpoints;
//! the per-commit walker that orchestrates them lives in
//! [`crate::git_push_replay_walker`].
//!
//! Three endpoint families are wrapped:
//!
//! * POST `git/blobs`, `git/trees`, `git/commits` — the create-side
//!   primitives the walker uses to upload bundle objects one at a time.
//! * GET `repos/{o}/{r}` and `repos/{o}/{r}/git/ref/heads/{branch}` —
//!   the lookup primitives the replay orchestrator uses to resolve
//!   the App-side default branch tip when an agent's push creates a
//!   new branch with no prior `expected_remote_head`. The tip is then
//!   fetched into the staging repo and passed by SHA to
//!   [`crate::git_push_replay_walker::plan_branch_creation_via_rev_list`].
//! * PATCH `repos/{o}/{r}/git/refs/heads/{branch}` — the publish step
//!   the promote workflow uses to fast-forward the App-side branch
//!   to the new commit chain the walker uploaded.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::core::RepoRef;
use crate::vm_git::{GitBranchName, GitBranchNameError, GitObjectId};

const ACCEPT_HEADER: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "2022-11-28";
/// GitHub's REST API rejects requests without a `User-Agent`. We set
/// it per-request rather than via `reqwest::ClientBuilder::user_agent`
/// so a caller that passes in a default-constructed `reqwest::Client`
/// still produces a working request — this is a protocol requirement,
/// not a client preference.
const USER_AGENT_HEADER: &str = "writ/0.1";

/// Authenticated client for one installation's Git Database namespace.
///
/// Holds the installation token and the resolved `api_base` so callers
/// can drive several blob/tree/commit creates with a single client. The
/// token is private and the hand-rolled `Debug` redacts it; the only
/// way to surface the token after construction is through the request
/// path, which writes it into the `Authorization: Bearer …` header and
/// nowhere else.
pub struct GitDataClient {
    http: reqwest::Client,
    api_base: String,
    token: String,
}

impl std::fmt::Debug for GitDataClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitDataClient")
            .field("api_base", &self.api_base)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitDataError {
    #[error("GitHub Git Data request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GitHub Git Data API returned {status}: {body}")]
    ApiError {
        status: reqwest::StatusCode,
        body: String,
    },
    /// GitHub returned a repo whose `default_branch` field is not a
    /// valid git branch name. The field is operator-set on GitHub,
    /// so a bad value is server-side data corruption rather than a
    /// transport issue — we surface it separately so the caller can
    /// distinguish "bad input from GitHub" from "transport error".
    #[error("GitHub returned an invalid default_branch name: {source}")]
    InvalidDefaultBranch {
        #[source]
        source: GitBranchNameError,
    },
    /// `GET /repos/{o}/{r}/git/ref/heads/{branch}` returned an
    /// object whose `type` is not `commit`. Branches in GitHub
    /// always point at commits; a non-commit object indicates either
    /// a misuse (caller passed a tag ref to a branch API) or a
    /// server-side anomaly. Either way the SHA can't be plugged into
    /// the per-commit walker's parent slot.
    #[error("ref {ref_name} resolved to object type {object_type:?} (expected 'commit')")]
    UnexpectedRefObjectType {
        ref_name: String,
        object_type: String,
    },
    /// A [`CommitRequest`] carried a `signature`, GitHub created the
    /// commit, and then reported `verification.verified = false`.
    ///
    /// Supplying a signature *is* the claim that the published commit
    /// will carry the Verified badge — that is the guarantee the whole
    /// replay path exists to provide. GitHub is the only authority on
    /// whether the signature actually verifies against the commit it
    /// assembled, so a `false` verdict means the guarantee is broken
    /// and the SHA must not travel on to branch publication. Returning
    /// it as an error strands the commit as an unreferenced object in
    /// the repo instead (harmless; GitHub garbage-collects it).
    #[error(
        "GitHub created signed commit {sha} but reported it as unverified (reason: {reason}); \
         refusing to publish an unverified commit"
    )]
    UnverifiedSignedCommit { sha: String, reason: String },
    /// A [`CommitRequest`] carried a `signature` and GitHub's response
    /// omitted the `verification` object entirely.
    ///
    /// Distinct from [`GitDataError::UnverifiedSignedCommit`] only in
    /// diagnosis — an absent verdict is not an affirmative one, so the
    /// Verified guarantee is equally unconfirmable and we equally
    /// refuse to publish. In practice this means talking to something
    /// that is not the GitHub API (a stale GHES, a proxy rewriting
    /// bodies), which is worth naming distinctly.
    #[error(
        "GitHub's response for signed commit {sha} carried no `verification` object, so the \
         Verified guarantee cannot be confirmed; refusing to publish"
    )]
    MissingVerification { sha: String },
}

impl GitDataClient {
    /// `api_base` is the GitHub REST API root *without* a trailing slash
    /// (e.g. `https://api.github.com`); the path segments for each
    /// endpoint are concatenated on. Tests pass a `wiremock` server URI
    /// in to swap the destination.
    pub fn new(
        http: reqwest::Client,
        api_base: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            http,
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

/// One row in a tree being uploaded to GitHub. The kind constrains
/// `mode` and `type` jointly so a caller can't write a (mode, type)
/// pair the API would reject — e.g. `040000` paired with `blob`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
    pub sha: GitObjectId,
}

/// What a tree entry points at. Each variant fixes both the file
/// `mode` and the object `type` GitHub expects, so the on-wire pair
/// is always valid by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeEntryKind {
    /// Regular file: mode `100644`, type `blob`.
    Blob,
    /// Executable file: mode `100755`, type `blob`.
    Executable,
    /// Symbolic link: mode `120000`, type `blob`. The referenced
    /// blob's content is the link target.
    Symlink,
    /// Subtree: mode `040000`, type `tree`.
    Subtree,
    /// Submodule pointer: mode `160000`, type `commit`. The SHA
    /// names a commit in another repository.
    Submodule,
}

impl TreeEntryKind {
    const fn mode(self) -> &'static str {
        match self {
            Self::Blob => "100644",
            Self::Executable => "100755",
            Self::Symlink => "120000",
            Self::Subtree => "040000",
            Self::Submodule => "160000",
        }
    }

    const fn object_type(self) -> &'static str {
        match self {
            Self::Blob | Self::Executable | Self::Symlink => "blob",
            Self::Subtree => "tree",
            Self::Submodule => "commit",
        }
    }
}

/// Name, email, and pre-formatted authoring timestamp of a Git
/// author or committer.
///
/// Construct via [`CommitIdentity::new`], which validates the
/// supplied `OffsetDateTime` by formatting it as RFC 3339 once and
/// caching the string. From that point the value is known-good for
/// the wire, so [`GitDataClient::create_commit`] cannot fail at
/// send time on a malformed date — the failure surfaces at the
/// boundary where it can be reported back to whichever bundle
/// commit produced the bad metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitIdentity {
    name: String,
    email: String,
    /// Pre-formatted RFC 3339 timestamp with sub-second precision
    /// truncated. Preserves the original timezone offset.
    date_rfc3339: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CommitIdentityError {
    /// The supplied `OffsetDateTime` is outside what RFC 3339 can
    /// represent (e.g. a sub-minute UTC offset, or a year outside
    /// `0000..=9999`). Git commit dates Git itself emits are
    /// always within range, so this typically indicates corrupted
    /// or hand-crafted bundle metadata.
    #[error("commit identity date cannot be formatted as RFC 3339: {0}")]
    Rfc3339Format(#[from] time::error::Format),
}

impl CommitIdentity {
    /// Validate the date by formatting it as RFC 3339 (seconds
    /// precision, original offset preserved) and store the result
    /// alongside the name/email. The whole struct is known
    /// wire-ready after this returns `Ok`.
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        date: time::OffsetDateTime,
    ) -> Result<Self, CommitIdentityError> {
        let date = date
            .replace_nanosecond(0)
            .expect("zero is always a valid nanosecond for OffsetDateTime");
        let date_rfc3339 = date.format(&time::format_description::well_known::Rfc3339)?;
        Ok(Self {
            name: name.into(),
            email: email.into(),
            date_rfc3339,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// The validated RFC 3339 representation of the authoring date,
    /// with seconds precision and the original timezone offset
    /// preserved. Round-tripping this string through
    /// [`time::OffsetDateTime::parse`] with the `Rfc3339` format
    /// description is guaranteed to succeed.
    pub fn date_rfc3339(&self) -> &str {
        &self.date_rfc3339
    }
}

/// Inputs to [`GitDataClient::create_commit`].
///
/// Bundled as a struct so the call site is readable and so adding
/// optional fields (notably `signature`) does not blow past
/// clippy's argument-count threshold.
///
/// `signature`, when `Some`, must be a detached PGP or SSH
/// signature over the canonical commit object the API would
/// construct from the other fields. GitHub validates the signature
/// against the supplied identities; if it does not match the
/// commit GitHub assembles, the published commit's
/// `verification.reason` reflects that mismatch.
#[derive(Clone, Debug)]
pub struct CommitRequest<'a> {
    pub tree: &'a GitObjectId,
    pub parents: &'a [GitObjectId],
    pub message: &'a str,
    pub author: &'a CommitIdentity,
    pub committer: &'a CommitIdentity,
    pub signature: Option<&'a str>,
}

/// Percent-encode a ref-path segment for inclusion in a URL.
///
/// Preserves the unreserved set (RFC 3986 §2.3: ALPHA / DIGIT /
/// `-` / `.` / `_` / `~`) and `/` (so the caller can pass a
/// hierarchical ref like `feature/foo` as a single string), and
/// percent-encodes every other byte. Operates on the byte
/// representation so UTF-8 multi-byte sequences are encoded one
/// byte at a time, which is how RFC 3986 specifies the transform
/// for non-ASCII octets.
///
/// Git's branch-naming rules permit several URL-reserved bytes
/// (`#`, `%`, `(`, `)`, `+`, `=`, etc.); without encoding, a name
/// like `release#1` would silently turn into `release` plus a
/// fragment, and `100%` would either be rejected as a malformed
/// escape or turn into mojibake.
fn percent_encode_ref_segment(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char);
            }
            _ => {
                write!(out, "%{byte:02X}").expect("write into String never fails");
            }
        }
    }
    out
}

fn identity_wire(identity: &CommitIdentity) -> CommitIdentityWire<'_> {
    CommitIdentityWire {
        name: &identity.name,
        email: &identity.email,
        date: &identity.date_rfc3339,
    }
}

#[derive(serde::Serialize)]
struct BlobCreateBody {
    content: String,
    encoding: &'static str,
}

#[derive(serde::Deserialize)]
struct BlobCreateResponse {
    sha: GitObjectId,
}

#[derive(serde::Serialize)]
struct TreeCreateBody<'a> {
    tree: Vec<TreeEntryWire<'a>>,
}

#[derive(serde::Serialize)]
struct TreeEntryWire<'a> {
    path: &'a str,
    mode: &'static str,
    #[serde(rename = "type")]
    object_type: &'static str,
    sha: &'a GitObjectId,
}

#[derive(serde::Deserialize)]
struct TreeCreateResponse {
    sha: GitObjectId,
}

#[derive(serde::Serialize)]
struct CommitCreateBody<'a> {
    message: &'a str,
    tree: &'a GitObjectId,
    parents: &'a [GitObjectId],
    author: CommitIdentityWire<'a>,
    committer: CommitIdentityWire<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct CommitIdentityWire<'a> {
    name: &'a str,
    email: &'a str,
    date: &'a str,
}

/// `POST /repos/{o}/{r}/git/commits` response. `verification` is
/// GitHub's verdict on the `signature` we sent: the API creates the
/// commit either way and reports the outcome here, so a 2xx status
/// alone does not mean the signature verified.
///
/// The field is `Option` because a response that omits it is a
/// distinguishable failure mode we want to report as such, not a
/// deserialisation error — see [`GitDataError::MissingVerification`].
#[derive(serde::Deserialize)]
struct CommitCreateResponse {
    sha: GitObjectId,
    #[serde(default)]
    verification: Option<CommitVerification>,
}

/// The subset of GitHub's `verification` block we act on. `reason` is
/// the machine-readable string (`valid`, `unsigned`, `unknown_key`,
/// `bad_email`, …) that tells an operator *why* a signature failed to
/// verify; it is `Option` because only `verified` is load-bearing.
#[derive(serde::Deserialize)]
struct CommitVerification {
    verified: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// `PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}` body. The
/// `force` field is always serialised (rather than relying on
/// GitHub's documented `force=false` default) so the wire trace is
/// self-describing: an operator inspecting a captured request sees
/// the intent explicitly rather than having to know the default.
#[derive(serde::Serialize)]
struct UpdateRefBody<'a> {
    sha: &'a GitObjectId,
    force: bool,
}

/// Subset of `GET /repos/{owner}/{repo}` we care about. The
/// response carries many other fields (description, language stats,
/// permissions, etc.) — serde with `deny_unknown_fields` would force
/// us to track every one of GitHub's schema additions, so we
/// deliberately accept extras and pull only the field we need.
#[derive(serde::Deserialize)]
struct RepoMetadataResponse {
    default_branch: String,
}

/// `GET /repos/{owner}/{repo}/git/ref/{ref}` response. The wire
/// shape names the inner object via the JSON key `object`, with the
/// JSON key `type` distinguishing commit / tag / etc. — `object_type`
/// is the Rust field name (Rust forbids `type` as an identifier here)
/// and serde renames it on deserialise.
#[derive(serde::Deserialize)]
struct GetRefResponse {
    object: GetRefObject,
}

#[derive(serde::Deserialize)]
struct GetRefObject {
    sha: GitObjectId,
    #[serde(rename = "type")]
    object_type: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn sample_repo() -> RepoRef {
        RepoRef::from_str("owner/name").unwrap()
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn client_against(server: &MockServer, token: &str) -> GitDataClient {
        GitDataClient::new(reqwest::Client::new(), server.uri(), token.to_string())
    }

    #[tokio::test]
    async fn create_blob_sends_base64_body_and_returns_sha() {
        let server = MockServer::start().await;
        let raw = b"hello\x00world\n";
        let encoded = BASE64_STANDARD.encode(raw);
        let returned = sample_object_id('a');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "content": encoded,
                "encoding": "base64",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                "url": format!("https://api.github.com/repos/owner/name/git/blobs/{}", returned.as_str()),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_blob(&sample_repo(), raw)
            .await
            .expect("blob create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_blob_surfaces_api_error_body_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(
                ResponseTemplate::new(422).set_body_json(json!({"message": "Validation Failed"})),
            )
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("Validation Failed"),
                    "ApiError body must echo the response payload so operators can diagnose: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_blob_surfaces_api_error_on_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("5xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 503);
                assert_eq!(body, "upstream unavailable");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_blob_round_trips_binary_content_unchanged() {
        // Bytes that would be silently mangled by a UTF-8 transport:
        // a NUL byte, a bare CR, an invalid UTF-8 lead byte, and a
        // high-bit byte that is not the start of a valid codepoint.
        // Base64 must survive all of these unmodified so the SHA the
        // walker plugs into the next tree matches what the staging
        // repo actually held.
        let raw: &[u8] = b"\x00\rgit\xc3\x28\xff\n";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .and(body_json(json!({
                "content": BASE64_STANDARD.encode(raw),
                "encoding": "base64",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('b').as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        client
            .create_blob(&sample_repo(), raw)
            .await
            .expect("binary content survives transport");
    }

    #[tokio::test]
    async fn create_blob_returns_http_error_when_response_sha_is_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection during deserialisation surfaces as a transport error: {err:?}",
        );
    }

    fn entry(path: &str, kind: TreeEntryKind, sha: GitObjectId) -> TreeEntry {
        TreeEntry {
            path: path.to_string(),
            kind,
            sha,
        }
    }

    #[test]
    fn tree_entry_kind_mode_and_type_match_github_wire_format() {
        // Lock the (mode, type) pairs so a typo in the const tables
        // would fail loudly. These are the values GitHub's API
        // documents and the only ones it accepts.
        let cases = [
            (TreeEntryKind::Blob, "100644", "blob"),
            (TreeEntryKind::Executable, "100755", "blob"),
            (TreeEntryKind::Symlink, "120000", "blob"),
            (TreeEntryKind::Subtree, "040000", "tree"),
            (TreeEntryKind::Submodule, "160000", "commit"),
        ];
        for (kind, mode, object_type) in cases {
            assert_eq!(kind.mode(), mode, "wrong mode for {kind:?}");
            assert_eq!(kind.object_type(), object_type, "wrong type for {kind:?}");
        }
    }

    #[tokio::test]
    async fn create_tree_sends_each_kind_with_correct_mode_and_type() {
        // One entry of every kind, so a regression in any (mode,
        // type) pair would mismatch the body matcher.
        let server = MockServer::start().await;
        let blob_sha = sample_object_id('a');
        let exec_sha = sample_object_id('b');
        let symlink_sha = sample_object_id('c');
        let subtree_sha = sample_object_id('d');
        let submodule_sha = sample_object_id('e');
        let returned = sample_object_id('f');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "tree": [
                    { "path": "README", "mode": "100644", "type": "blob", "sha": blob_sha.as_str() },
                    { "path": "scripts/run", "mode": "100755", "type": "blob", "sha": exec_sha.as_str() },
                    { "path": "link", "mode": "120000", "type": "blob", "sha": symlink_sha.as_str() },
                    { "path": "vendor", "mode": "040000", "type": "tree", "sha": subtree_sha.as_str() },
                    { "path": "submod", "mode": "160000", "type": "commit", "sha": submodule_sha.as_str() },
                ],
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let entries = vec![
            entry("README", TreeEntryKind::Blob, blob_sha),
            entry("scripts/run", TreeEntryKind::Executable, exec_sha),
            entry("link", TreeEntryKind::Symlink, symlink_sha),
            entry("vendor", TreeEntryKind::Subtree, subtree_sha),
            entry("submod", TreeEntryKind::Submodule, submodule_sha),
        ];
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect("tree create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_tree_with_no_entries_posts_empty_tree_array() {
        // Initial commits may have an empty root tree; the walker
        // relies on this call succeeding and getting the empty-tree
        // SHA back.
        let server = MockServer::start().await;
        let returned = sample_object_id('0');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(json!({ "tree": [] })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_tree(&sample_repo(), &[])
            .await
            .expect("empty tree create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_tree_surfaces_api_error_body_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "path 'foo' is invalid"})),
            )
            .mount(&server)
            .await;

        let entries = vec![entry("foo", TreeEntryKind::Blob, sample_object_id('a'))];
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("path 'foo' is invalid"),
                    "ApiError body must echo the response payload: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_tree_returns_http_error_when_response_sha_is_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let entries = vec![entry("foo", TreeEntryKind::Blob, sample_object_id('a'))];
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection surfaces as a transport error: {err:?}",
        );
    }

    fn sample_identity(name: &str, date: time::OffsetDateTime) -> CommitIdentity {
        CommitIdentity::new(name, format!("{name}@example.invalid"), date)
            .expect("test datetime is RFC 3339 representable")
    }

    fn unsigned_request<'a>(
        tree: &'a GitObjectId,
        parents: &'a [GitObjectId],
        message: &'a str,
        author: &'a CommitIdentity,
        committer: &'a CommitIdentity,
    ) -> CommitRequest<'a> {
        CommitRequest {
            tree,
            parents,
            message,
            author,
            committer,
            signature: None,
        }
    }

    #[test]
    fn commit_identity_drops_subsecond_precision_on_date() {
        // The wire format GitHub documents is YYYY-MM-DDTHH:MM:SSZ;
        // emitting sub-second digits is technically out of spec and
        // would let a caller-constructed sub-second `OffsetDateTime`
        // surface a deviation. Truncating at construction keeps the
        // wire shape stable.
        use time::macros::datetime;
        let identity = CommitIdentity::new(
            "Alice",
            "alice@example.invalid",
            datetime!(2024-01-15 10:30:45.123456789 UTC),
        )
        .expect("UTC date is RFC 3339 representable");
        assert_eq!(identity.date_rfc3339, "2024-01-15T10:30:45Z");
    }

    #[test]
    fn commit_identity_preserves_non_utc_offset() {
        // Git commits carry the original author/committer offset
        // (e.g. `+0530`); we forward it verbatim so the replayed
        // commit's timestamp is faithful to the bundle.
        use time::macros::datetime;
        let identity = CommitIdentity::new(
            "Alice",
            "alice@example.invalid",
            datetime!(2024-01-15 10:30:45 +05:30),
        )
        .expect("+05:30 offset is RFC 3339 representable");
        assert_eq!(identity.date_rfc3339, "2024-01-15T10:30:45+05:30");
    }

    #[test]
    fn commit_identity_rejects_subminute_offset() {
        // RFC 3339 only allows offsets in whole minutes. `time` lets
        // you build a sub-minute offset with `UtcOffset::from_hms`,
        // and the RFC 3339 formatter rejects it. The validated
        // constructor must surface that as an error rather than
        // panicking inside `create_commit` later.
        use time::macros::datetime;
        let subminute_offset =
            time::UtcOffset::from_hms(0, 0, 30).expect("seconds-precision offset constructs");
        let weird_date = datetime!(2024-01-15 10:30:45 UTC).replace_offset(subminute_offset);
        let err = CommitIdentity::new("Alice", "alice@example.invalid", weird_date)
            .expect_err("sub-minute offset must not be accepted");
        assert!(
            matches!(err, CommitIdentityError::Rfc3339Format(_)),
            "expected an Rfc3339Format error, got {err:?}",
        );
    }

    #[tokio::test]
    async fn create_commit_sends_message_tree_parents_and_identities() {
        // Standard non-initial commit with one parent. Asserts that
        // every documented field is on the wire and that the
        // returned sha is propagated up.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let parent_sha = sample_object_id('b');
        let returned = sample_object_id('c');
        let author = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let committer = sample_identity("WritApp", datetime!(2024-01-15 10:31:00 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "message": "Fix the thing",
                "tree": tree_sha.as_str(),
                "parents": [parent_sha.as_str()],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "WritApp",
                    "email": "WritApp@example.invalid",
                    "date": "2024-01-15T10:31:00Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let parents = std::slice::from_ref(&parent_sha);
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, parents, "Fix the thing", &author, &committer),
            )
            .await
            .expect("commit create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_sends_empty_parents_for_initial_commit() {
        // Initial commits have no parents; the walker relies on
        // sending `[]` and the API accepting it.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('c');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Initial",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &[], "Initial", &ident, &ident),
            )
            .await
            .expect("initial commit ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_sends_all_parents_for_merge_commit() {
        // Octopus merges have several parents; both must appear in
        // order so GitHub records the merge topology correctly.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let parent_a = sample_object_id('b');
        let parent_b = sample_object_id('c');
        let returned = sample_object_id('d');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Merge branch",
                "tree": tree_sha.as_str(),
                "parents": [parent_a.as_str(), parent_b.as_str()],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let parents = [parent_a, parent_b];
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &parents, "Merge branch", &ident, &ident),
            )
            .await
            .expect("merge commit ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_surfaces_api_error_body_on_4xx() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "tree sha does not exist"})),
            )
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree, &[], "msg", &ident, &ident),
            )
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("tree sha does not exist"),
                    "ApiError body must echo the response payload: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_commit_returns_http_error_when_response_sha_is_invalid() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree, &[], "msg", &ident, &ident),
            )
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection surfaces as a transport error: {err:?}",
        );
    }

    #[tokio::test]
    async fn create_commit_omits_signature_field_when_none() {
        // With no signature, the field must be absent from the JSON
        // body — not present-with-null — so GitHub doesn't reject the
        // request and the absence is unambiguous on the wire.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('b');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        // Strict matcher: the absence of `signature` from this JSON
        // object means the wire body must not include the key at all.
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "msg",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &[], "msg", &ident, &ident),
            )
            .await
            .expect("unsigned commit create ok");
    }

    #[tokio::test]
    async fn create_commit_forwards_signature_field_when_some() {
        // Verified commits require a detached signature on the
        // wire. The wrapper must pass it through verbatim; producing
        // and validating it is the replay walker's responsibility.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('b');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let signature = "-----BEGIN PGP SIGNATURE-----\n\nfakeArmoredSignaturePayload\n-----END PGP SIGNATURE-----\n";

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Signed commit",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "signature": signature,
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                // GitHub reports its verdict on the signature we sent;
                // a signed create-commit only yields a SHA when that
                // verdict is affirmative, so the mock must carry it.
                "verification": { "verified": true, "reason": "valid" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = CommitRequest {
            tree: &tree_sha,
            parents: &[],
            message: "Signed commit",
            author: &ident,
            committer: &ident,
            signature: Some(signature),
        };
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(&sample_repo(), &request)
            .await
            .expect("signed commit create ok");
        assert_eq!(got, returned);
    }

    /// A signed create-commit whose response says GitHub could not
    /// verify the signature must fail. The whole point of supplying a
    /// signature is that the published commit carries the Verified
    /// badge; if GitHub disagrees, the SHA must not escape this
    /// function and reach branch publication.
    #[tokio::test]
    async fn create_commit_rejects_signed_commit_github_reports_unverified() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        let returned = sample_object_id('b');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                "verification": {
                    "verified": false,
                    "reason": "unknown_key",
                    "signature": "-----BEGIN SSH SIGNATURE-----\n…\n",
                    "payload": "tree …",
                },
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let request = CommitRequest {
            tree: &tree,
            parents: &[],
            message: "msg",
            author: &ident,
            committer: &ident,
            signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
        };
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(&sample_repo(), &request)
            .await
            .expect_err("an unverified signed commit must not be returned as a success");
        match err {
            GitDataError::UnverifiedSignedCommit { sha, reason } => {
                assert_eq!(sha, returned.as_str());
                assert_eq!(reason, "unknown_key");
            }
            other => panic!("expected UnverifiedSignedCommit, got {other:?}"),
        }
    }

    /// GitHub omitting the `verification` object entirely from a
    /// signed commit's response is just as unusable as a `false`
    /// verdict: we cannot confirm the Verified guarantee, so we refuse
    /// rather than publish and hope.
    #[tokio::test]
    async fn create_commit_rejects_signed_commit_with_no_verification_object() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        let returned = sample_object_id('b');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let request = CommitRequest {
            tree: &tree,
            parents: &[],
            message: "msg",
            author: &ident,
            committer: &ident,
            signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
        };
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(&sample_repo(), &request)
            .await
            .expect_err("a signed commit with no verification verdict must not succeed");
        assert!(
            matches!(err, GitDataError::MissingVerification { ref sha } if sha == returned.as_str()),
            "expected MissingVerification, got {err:?}",
        );
    }

    /// The happy path: signature supplied, GitHub reports
    /// `verified: true`, the SHA flows back to the walker.
    #[tokio::test]
    async fn create_commit_accepts_signed_commit_github_reports_verified() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        let returned = sample_object_id('b');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                "verification": {
                    "verified": true,
                    "reason": "valid",
                },
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let request = CommitRequest {
            tree: &tree,
            parents: &[],
            message: "msg",
            author: &ident,
            committer: &ident,
            signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
        };
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(&sample_repo(), &request)
            .await
            .expect("verified signed commit is the happy path");
        assert_eq!(got, returned);
    }

    /// An *unsigned* create-commit never promised a Verified badge, so
    /// the (inevitably `verified: false`) verdict is not an error. The
    /// pre-promote bring-up flows and test fixtures depend on this.
    #[tokio::test]
    async fn create_commit_tolerates_unverified_verdict_when_request_is_unsigned() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        let returned = sample_object_id('b');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                "verification": {
                    "verified": false,
                    "reason": "unsigned",
                },
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree, &[], "msg", &ident, &ident),
            )
            .await
            .expect("an unsigned request makes no Verified claim to break");
        assert_eq!(got, returned);
    }

    proptest::proptest! {
        // Each case stands up a wiremock server, so keep the case
        // count modest; the input space here is tiny (2 × 3 shapes)
        // and this many cases covers it many times over.
        #![proptest_config(proptest::test_runner::Config::with_cases(24))]

        /// The invariant the replay path leans on: `create_commit`
        /// returns a SHA **exactly** when either the request carried no
        /// signature (no Verified claim was made) or GitHub affirmed
        /// `verification.verified == true`. Every other combination —
        /// signed-and-refuted, signed-and-no-verdict — must be an error,
        /// whatever `reason` string GitHub attaches.
        #[test]
        fn signed_create_commit_succeeds_exactly_when_github_reports_verified(
            signed in proptest::bool::ANY,
            verification in proptest::option::of((proptest::bool::ANY, "[a-z_]{1,16}")),
        ) {
            use time::macros::datetime;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let server = MockServer::start().await;
                let returned = sample_object_id('b');
                let mut body = json!({ "sha": returned.as_str() });
                if let Some((verified, reason)) = &verification {
                    body["verification"] = json!({ "verified": verified, "reason": reason });
                }
                Mock::given(method("POST"))
                    .and(path("/repos/owner/name/git/commits"))
                    .respond_with(ResponseTemplate::new(201).set_body_json(body))
                    .mount(&server)
                    .await;

                let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
                let tree = sample_object_id('a');
                let request = CommitRequest {
                    tree: &tree,
                    parents: &[],
                    message: "msg",
                    author: &ident,
                    committer: &ident,
                    signature: signed.then_some(
                        "-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n",
                    ),
                };
                let client = client_against(&server, "ghs_fake_token");
                let result = client.create_commit(&sample_repo(), &request).await;

                let should_succeed =
                    !signed || matches!(verification, Some((true, _)));
                proptest::prop_assert_eq!(
                    result.is_ok(),
                    should_succeed,
                    "signed={:?} verification={:?} gave {:?}",
                    signed,
                    verification,
                    result.map(|sha| sha.as_str().to_string()),
                );
                Ok(())
            })?;
        }
    }

    #[test]
    fn debug_redacts_token() {
        let client =
            GitDataClient::new(reqwest::Client::new(), "https://api.example", "ghs_secret");
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("ghs_secret"),
            "Debug must not echo the token: {rendered}",
        );
        assert!(
            rendered.contains("<redacted>"),
            "Debug should label the redacted slot: {rendered}",
        );
    }

    // ----- get_default_branch tests ---------------------------------

    #[tokio::test]
    async fn get_default_branch_sends_authed_get_and_parses_default_branch_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 42,
                "name": "name",
                "full_name": "owner/name",
                "default_branch": "main",
                "private": false,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = client
            .get_default_branch(&sample_repo())
            .await
            .expect("default branch lookup ok");
        assert_eq!(branch.as_str(), "main");
    }

    #[tokio::test]
    async fn get_default_branch_accepts_non_main_default_branch_name() {
        // Older or operator-customised repos use `master`, `trunk`,
        // etc. The walker has no opinion on what the operator chose;
        // any valid branch name flows through.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "default_branch": "trunk",
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = client
            .get_default_branch(&sample_repo())
            .await
            .expect("default branch lookup ok");
        assert_eq!(branch.as_str(), "trunk");
    }

    #[tokio::test]
    async fn get_default_branch_surfaces_api_error_body_on_404() {
        // Repo doesn't exist (or the App doesn't have access).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .get_default_branch(&sample_repo())
            .await
            .expect_err("404 must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 404);
                assert!(body.contains("Not Found"), "echo body: {body:?}");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_default_branch_rejects_invalid_branch_name_from_github() {
        // Defensive parsing: a default_branch value that fails
        // GitBranchName validation surfaces as a typed error rather
        // than a panic or a silent coerce. GitHub should never emit
        // this, but if it does, we want the failure mode to be
        // diagnosable rather than mysterious.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "default_branch": "..",
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .get_default_branch(&sample_repo())
            .await
            .expect_err("malformed branch name must not return silently");
        assert!(
            matches!(err, GitDataError::InvalidDefaultBranch { .. }),
            "expected InvalidDefaultBranch, got {err:?}",
        );
    }

    #[tokio::test]
    async fn get_default_branch_returns_http_error_when_default_branch_missing() {
        // Response missing the `default_branch` field is a transport
        // / schema issue and surfaces as a transport error via serde.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 42,
                "name": "name",
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .get_default_branch(&sample_repo())
            .await
            .expect_err("missing default_branch must not succeed");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "expected Http error on missing field, got {err:?}",
        );
    }

    // ----- get_branch_head tests ------------------------------------

    #[tokio::test]
    async fn get_branch_head_sends_authed_get_and_returns_commit_sha() {
        let server = MockServer::start().await;
        let returned = sample_object_id('a');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/main",
                "node_id": "ignored",
                "url": "https://api.github.com/repos/owner/name/git/refs/heads/main",
                "object": {
                    "sha": returned.as_str(),
                    "type": "commit",
                    "url": format!(
                        "https://api.github.com/repos/owner/name/git/commits/{}",
                        returned.as_str(),
                    ),
                },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let sha = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect("branch head lookup ok");
        assert_eq!(sha, returned);
    }

    #[test]
    fn percent_encode_ref_segment_preserves_unreserved_and_slash_and_encodes_others() {
        // Unreserved set per RFC 3986 §2.3 plus '/' for ref hierarchy:
        // pass through unchanged.
        assert_eq!(
            percent_encode_ref_segment("AZaz09-._~/main"),
            "AZaz09-._~/main",
        );
        // URL-reserved bytes that git nonetheless accepts in branch
        // names: encode as %HH (uppercase, RFC 3986 §2.1).
        assert_eq!(percent_encode_ref_segment("release#1"), "release%231");
        assert_eq!(percent_encode_ref_segment("100%"), "100%25");
        assert_eq!(
            percent_encode_ref_segment("feat(area)+v2"),
            "feat%28area%29%2Bv2",
        );
        // UTF-8 multi-byte sequence encoded byte-by-byte (RFC 3986
        // §2.5): the 'é' in 'café' is 0xC3 0xA9.
        assert_eq!(percent_encode_ref_segment("café"), "caf%C3%A9");
    }

    /// Regression test for the URL-reserved-bytes issue: a branch
    /// name git considers valid but which contains `#` or `%` must
    /// reach GitHub at the correctly-encoded path. Without
    /// percent-encoding, `release#1` would 404 against GitHub
    /// because the `#` turns into a URL fragment.
    #[tokio::test]
    async fn get_branch_head_percent_encodes_url_reserved_bytes_in_branch_name() {
        let server = MockServer::start().await;
        let returned = sample_object_id('d');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/release%231"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/release#1",
                "object": { "sha": returned.as_str(), "type": "commit" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("release#1").unwrap();
        let sha = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect("URL-reserved bytes must be percent-encoded");
        assert_eq!(sha, returned);
    }

    #[tokio::test]
    async fn get_branch_head_passes_slashes_in_branch_name_through_url_path() {
        // `feature/foo` is a valid git branch name. The Git Database
        // API treats the ref path as hierarchical, so slashes belong
        // in the path literally — not percent-encoded.
        let server = MockServer::start().await;
        let returned = sample_object_id('b');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/feature/foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/feature/foo",
                "object": {
                    "sha": returned.as_str(),
                    "type": "commit",
                },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("feature/foo").unwrap();
        let sha = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect("nested branch head lookup ok");
        assert_eq!(sha, returned);
    }

    #[tokio::test]
    async fn get_branch_head_surfaces_api_error_body_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"message": "Branch not found"})),
            )
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect_err("404 must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 404);
                assert!(body.contains("Branch not found"), "echo body: {body:?}");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_head_rejects_response_pointing_at_non_commit() {
        // Defensive: branches always point at commits, so a `tag`
        // (or anything else) means we'd hand back a SHA the walker
        // would plug into a parent slot where only commit SHAs are
        // valid. Refuse at the boundary.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": {
                    "sha": sample_object_id('c').as_str(),
                    "type": "tag",
                },
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect_err("non-commit ref target must be rejected");
        match err {
            GitDataError::UnexpectedRefObjectType {
                ref_name,
                object_type,
            } => {
                assert_eq!(ref_name, "refs/heads/main");
                assert_eq!(object_type, "tag");
            }
            other => panic!("expected UnexpectedRefObjectType, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_head_returns_http_error_when_response_sha_is_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": {
                    "sha": "not a valid sha",
                    "type": "commit",
                },
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .get_branch_head(&sample_repo(), &branch)
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection surfaces as transport error: {err:?}",
        );
    }

    #[tokio::test]
    async fn update_ref_sends_patch_with_sha_and_force_false_returns_ok_on_200() {
        let server = MockServer::start().await;
        let new_head = sample_object_id('a');
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "sha": new_head.as_str(),
                "force": false,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/main",
                "object": { "sha": new_head.as_str(), "type": "commit" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        client
            .update_ref(&sample_repo(), &branch, &new_head)
            .await
            .expect("fast-forward update ok");
    }

    /// Regression: the URL-grammar asymmetry between `GET .../ref/...`
    /// (singular) and `PATCH .../refs/...` (plural) is the actual
    /// GitHub API. A typo here is undetectable by clippy/typechecker
    /// and would 404 silently against the real API, so the path is
    /// asserted explicitly.
    #[tokio::test]
    async fn update_ref_uses_plural_refs_path_segment() {
        let server = MockServer::start().await;
        let new_head = sample_object_id('b');
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/main",
                "object": { "sha": new_head.as_str(), "type": "commit" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        // A separate mount that responds 404 to the singular path —
        // if `update_ref` accidentally used `.../ref/...` this mock
        // would match and the test would fail.
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"message": "wrong path"})),
            )
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        client
            .update_ref(&sample_repo(), &branch, &new_head)
            .await
            .expect("plural `refs` path must reach the mock");
    }

    /// A 422 from GitHub is the documented "not a fast forward"
    /// failure mode. The body carries the GitHub-side reason and must
    /// reach the operator unchanged so they can distinguish "the
    /// walker chain doesn't descend from the current tip" from other
    /// 422 cases (e.g. malformed sha).
    #[tokio::test]
    async fn update_ref_surfaces_422_as_api_error_with_body() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "Update is not a fast forward"})),
            )
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .update_ref(&sample_repo(), &branch, &sample_object_id('c'))
            .await
            .expect_err("422 must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("not a fast forward"),
                    "ApiError body must echo GitHub's reason: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_ref_surfaces_5xx_as_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .update_ref(&sample_repo(), &branch, &sample_object_id('d'))
            .await
            .expect_err("5xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 503);
                assert_eq!(body, "upstream unavailable");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_ref_percent_encodes_url_reserved_bytes_in_branch_name() {
        let server = MockServer::start().await;
        let new_head = sample_object_id('e');
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/release%231"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/release#1",
                "object": { "sha": new_head.as_str(), "type": "commit" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("release#1").unwrap();
        client
            .update_ref(&sample_repo(), &branch, &new_head)
            .await
            .expect("URL-reserved bytes must be percent-encoded");
    }

    #[tokio::test]
    async fn update_ref_passes_slashes_in_branch_name_through_url_path() {
        let server = MockServer::start().await;
        let new_head = sample_object_id('f');
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/feature/foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/heads/feature/foo",
                "object": { "sha": new_head.as_str(), "type": "commit" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("feature/foo").unwrap();
        client
            .update_ref(&sample_repo(), &branch, &new_head)
            .await
            .expect("nested branch ref must pass slashes through");
    }
}
