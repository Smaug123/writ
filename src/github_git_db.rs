//! GitHub Git Database REST client used by the broker's push-replay engine.
//!
//! Replay re-creates every commit between the upstream branch tip and a
//! VM-supplied bundle tip via the GitHub `git/blobs`, `git/trees`, and
//! `git/commits` endpoints under the host App's identity, so the published
//! commits land with the Verified badge while preserving provenance back
//! to the bundle. This module exposes typed wrappers for those endpoints;
//! the per-commit walker that orchestrates them lives in
//! [`crate::git_push_walker`].
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
//!   [`crate::git_push_walker::plan_branch_creation_via_rev_list`].
//! * PATCH `repos/{o}/{r}/git/refs/heads/{branch}` — the publish step
//!   the promote workflow uses to fast-forward the App-side branch
//!   to the new commit chain the walker uploaded.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::core::RepoRef;
use crate::vm_git::{GitBranchName, GitBranchNameError, GitObjectId};

/// The `GitDataClient` request methods (blob/tree/commit creation, ref
/// read/update) live here; the struct and its supporting types stay in this
/// module. Split out to keep `github_git_db.rs` readable.
mod client;

/// Per-request bounds for the Git Data transport.
///
/// `reqwest`'s defaults are *no* connect timeout, *no* read timeout and
/// *no* total timeout, so a `reqwest::Client::new()` parked against a
/// black-holed or slow-drip endpoint waits forever. That is never
/// acceptable here: the promote path issues these requests with an
/// approve attempt row in flight, so an unbounded request wedges the
/// staged push (and, once the attempt is `Uncertain`, blocks any
/// concurrent reject) until the broker is killed. Bound every phase.
///
/// The three bounds:
///
/// * `connect` — TCP/TLS handshake only. Tight, so a black-holed route
///   fails fast instead of eating the whole request budget.
/// * `small_call` — wall-clock ceiling for the fixed-size control
///   calls (ref GET, repo-metadata GET, ref PATCH). Their request and
///   response bodies are a few hundred bytes by construction, so
///   elapsed time above this is a degraded server or a failed network,
///   never a legitimate slow transfer.
/// * `total` — wall-clock ceiling on any request, and the *only* time
///   bound the object uploads (blob, tree and commit creates) run
///   under besides `connect`. Their bodies scale with repo content —
///   a blob or a commit message up to the staging repo's 256 MiB
///   per-object ceiling, a tree with one wire entry per row — which
///   legitimately takes minutes on a slow uplink.
///
/// A per-phase "idle gap" bound would be strictly nicer for the upload
/// (fail on silence in 30 s instead of on the 300 s ceiling), but
/// reqwest's builder-level `read_timeout` does not implement one: it
/// arms a flat deadline at dispatch that runs until the response
/// *headers* arrive, so the entire upload counts against it and any
/// blob taking longer than the bound is killed mid-transfer despite
/// making progress. Hence: no `read_timeout` anywhere, `small_call`
/// applied per-request to the metadata calls, and the upload bounded
/// by `total` alone. Bounded-but-slower beats wrongly-failed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GitDataTimeouts {
    connect: Duration,
    small_call: Duration,
    total: Duration,
}

/// TCP/TLS handshake ceiling. Matches [`crate::github`]'s minter client.
const GIT_DATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Wall-clock ceiling for a metadata request. Above this GitHub is
/// either degraded or the network has failed.
const GIT_DATA_SMALL_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-request ceiling. Deliberately much larger than `small_call`:
/// a single blob create can carry up to the staging repo's per-object
/// ceiling (256 MiB, base64-expanded), and a slow uplink must be able
/// to finish. It exists to bound the pathological case, not the slow
/// one.
const GIT_DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

impl GitDataTimeouts {
    /// The bounds every production Git Data call runs under.
    pub const fn production() -> Self {
        Self {
            connect: GIT_DATA_CONNECT_TIMEOUT,
            small_call: GIT_DATA_SMALL_CALL_TIMEOUT,
            total: GIT_DATA_TOTAL_TIMEOUT,
        }
    }

    /// Arbitrary bounds. Tests use this to drive the timeout paths
    /// without waiting out the production values.
    pub const fn new(connect: Duration, small_call: Duration, total: Duration) -> Self {
        Self {
            connect,
            small_call,
            total,
        }
    }
}

/// The bounded HTTP transport every Git Data client is driven through:
/// a connection pool plus the parsed TLS root store, with
/// [`GitDataTimeouts`] already applied.
///
/// Separate from [`GitDataClient`] because the two halves have different
/// lifetimes and *very* different costs. The credentials (`api_base`,
/// installation token) are per-approve — a token is minted fresh for each
/// one — and cost nothing to carry. The transport is per-broker and
/// expensive: `reqwest`'s `rustls-tls-native-roots` backend reads and
/// parses the platform root store inside every `ClientBuilder::build()`,
/// which measures at ~7 s for a process's first build on macOS and ~80 ms
/// steady-state, and each build also starts an empty connection pool that
/// forfeits every established TLS session. Cloning one, by contrast, is an
/// `Arc` bump.
///
/// So the broker builds one at boot ([`crate::server::BrokerState`]) and
/// every approve borrows it. Holding this type is what makes "the transport
/// is shared" a fact of the call graph rather than a convention: the approve
/// pipeline is handed a client and has no way to build a transport of its
/// own.
///
/// Constructing it from [`GitDataTimeouts`] (rather than accepting a
/// prebuilt `reqwest::Client`) keeps the older invariant intact too — there
/// is no way to reach the Git Data endpoints over an unbounded transport.
#[derive(Clone, Debug)]
pub struct GitDataHttp {
    http: reqwest::Client,
    /// Carried alongside the client because it is applied per-request
    /// rather than at build time; see [`GitDataTimeouts`].
    small_call: Duration,
}

#[cfg(test)]
thread_local! {
    /// Transports built on *this thread*, so a test can assert that an
    /// operation builds none without a timing measurement.
    ///
    /// Thread-local rather than a process-wide atomic because the test
    /// harness runs tests in parallel on one process: a global counter
    /// would fold other tests' builds into the delta and make the
    /// assertion racy. `#[cfg(test)]` — the production build carries
    /// neither the counter nor the increment.
    static TRANSPORTS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many [`GitDataHttp`]s the calling thread has built. Only meaningful
/// as a difference measured across the operation under test.
#[cfg(test)]
pub(crate) fn transports_built_on_this_thread() -> usize {
    TRANSPORTS_BUILT.with(std::cell::Cell::get)
}

impl GitDataHttp {
    /// Build the transport. Expensive (see the type docs) — call once per
    /// broker, not once per request.
    pub fn new(timeouts: GitDataTimeouts) -> Self {
        #[cfg(test)]
        TRANSPORTS_BUILT.with(|built| built.set(built.get() + 1));
        debug_assert!(
            !timeouts.connect.is_zero()
                && !timeouts.small_call.is_zero()
                && !timeouts.total.is_zero(),
            "a zero timeout fails every request immediately",
        );
        debug_assert!(
            timeouts.total >= timeouts.small_call,
            "a total timeout below the small-call bound makes `small_call` meaningless",
        );
        let http = reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.total)
            .build()
            .expect("reqwest client constructs with timeouts set");
        Self {
            http,
            small_call: timeouts.small_call,
        }
    }

    /// The transport every production Git Data client runs over.
    pub fn production() -> Self {
        Self::new(GitDataTimeouts::production())
    }
}

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
///
/// The transport is *borrowed* from a shared [`GitDataHttp`], not built
/// here: constructing one of these is meant to be cheap enough to do per
/// approve, which is exactly as often as the token changes.
pub struct GitDataClient {
    http: reqwest::Client,
    /// Per-request override applied to the fixed-size control calls
    /// (see [`GitDataTimeouts`]); the object uploads (`create_blob`,
    /// `create_tree`, `create_commit`) deliberately run without it,
    /// under the client-level `total` ceiling only.
    small_call: Duration,
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
mod tests;
