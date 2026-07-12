//! A stateful fake GitHub for pipeline tests (test-only).
//!
//! `wiremock`'s static request/response matching can't answer the
//! question the crash harness needs answered — *"is the branch where
//! the audit log claims it is?"* — so this module mounts stateful
//! responders over a shared [`GitHubModel`] instead: an object store,
//! a refs map with real fast-forward `PATCH` semantics, and a request
//! log. The model is the harness's ground truth: pre- vs post-PATCH
//! crashes are classified by what the fake *actually received*, never
//! by the audit log under test.
//!
//! Implemented endpoints (the six the Git Data client uses, plus the
//! installation-token mint):
//!
//! * `POST /repos/{o}/{n}/git/blobs` / `git/trees` / `git/commits` —
//!   store an object, hand back a model-issued (opaque, deterministic)
//!   SHA. Signed commit creates answer with an affirmative
//!   `verification` block, unsigned ones with `reason: "unsigned"`,
//!   matching the contract `GitDataClient::create_commit` enforces.
//! * `GET /repos/{o}/{n}/git/ref/heads/{branch}` — read the refs map.
//! * `GET /repos/{o}/{n}` — repo metadata (`default_branch`).
//! * `PATCH /repos/{o}/{n}/git/refs/heads/{branch}` — move the ref iff
//!   the new SHA descends from the current tip in the model's commit
//!   graph (GitHub's `force=false` check is descent-from-current, not
//!   compare-and-swap — which is exactly what makes lease-TOCTOU bugs
//!   expressible here); otherwise 422.
//! * `POST /app/installations/{id}/access_tokens` — echoes the
//!   requested permissions and repository back (the real minter
//!   refuses any drift, so the echo is the least-magic way to satisfy
//!   it) with a one-hour expiry.
//!
//! Branch names are matched on the raw URL path segment, undecoded;
//! use plain names (no URL-reserved bytes) in tests driving this fake.
//!
//! SHAs the model issues are `{:040x}`-formatted counters — opaque and
//! deterministic, nothing like real git SHAs, which is fine because
//! every consumer treats them as opaque. Real SHAs enter the model via
//! [`FakeGitHub::set_ref`] / [`FakeGitHub::seed_commit`] (e.g. the
//! staged push's `expected_remote_head`), which is what lets uploaded
//! commit chains whose first parent is a real SHA pass the descent
//! check.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// One observed HTTP request, in arrival order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestRecord {
    pub(crate) serial: usize,
    pub(crate) method: String,
    pub(crate) path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObjectRecord {
    Blob,
    Tree,
    Commit { parents: Vec<String> },
}

/// The mutable world the responders share. Locked per request — the
/// mock server serialises nothing, the mutex does.
#[derive(Debug)]
pub(crate) struct GitHubModel {
    objects: HashMap<String, ObjectRecord>,
    refs: HashMap<String, String>,
    /// Every value each ref has ever held, including the initial seed —
    /// `ref_history` is how the oracle asserts "the branch moved at
    /// most once" without trusting the audit log under test.
    ref_history: HashMap<String, Vec<String>>,
    requests: Vec<RequestRecord>,
    default_branch: String,
    next_sha: u64,
}

impl GitHubModel {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
            refs: HashMap::new(),
            ref_history: HashMap::new(),
            requests: Vec::new(),
            default_branch: "main".to_string(),
            next_sha: 1,
        }
    }

    fn record(&mut self, req: &Request) {
        self.requests.push(RequestRecord {
            serial: self.requests.len(),
            method: req.method.to_string(),
            path: req.url.path().to_string(),
        });
    }

    fn mint_sha(&mut self) -> String {
        let sha = format!("{:040x}", self.next_sha);
        self.next_sha += 1;
        sha
    }

    fn set_ref(&mut self, branch: &str, sha: &str) {
        self.objects
            .entry(sha.to_string())
            .or_insert(ObjectRecord::Commit { parents: vec![] });
        self.refs.insert(branch.to_string(), sha.to_string());
        self.ref_history
            .entry(branch.to_string())
            .or_default()
            .push(sha.to_string());
    }

    /// Is `descendant` reachable from itself down to `ancestor` via
    /// the commit graph the model knows? Unknown parents terminate the
    /// walk (they descend from nothing the model can verify).
    fn descends_from(&self, descendant: &str, ancestor: &str) -> bool {
        let mut stack = vec![descendant.to_string()];
        let mut seen = std::collections::HashSet::new();
        while let Some(sha) = stack.pop() {
            if sha == ancestor {
                return true;
            }
            if !seen.insert(sha.clone()) {
                continue;
            }
            if let Some(ObjectRecord::Commit { parents }) = self.objects.get(&sha) {
                stack.extend(parents.iter().cloned());
            }
        }
        false
    }
}

fn ref_body(branch: &str, sha: &str) -> serde_json::Value {
    json!({
        "ref": format!("refs/heads/{branch}"),
        "object": { "sha": sha, "type": "commit" },
    })
}

/// Strip `/repos/{o}/{n}/git/ref(s)/heads/` from a request path,
/// yielding the raw (undecoded) branch segment.
fn branch_from_path<'a>(req_path: &'a str, route_prefix: &str) -> &'a str {
    req_path
        .strip_prefix(route_prefix)
        .expect("route matcher guarantees the prefix")
}

struct WithModel<F>(Arc<Mutex<GitHubModel>>, F);

impl<F> Respond for WithModel<F>
where
    F: Fn(&mut GitHubModel, &Request) -> ResponseTemplate + Send + Sync,
{
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut model = self.0.lock().expect("GitHubModel poisoned");
        model.record(request);
        (self.1)(&mut model, request)
    }
}

/// The running fake: a `wiremock` server plus handles into the model.
pub(crate) struct FakeGitHub {
    server: MockServer,
    model: Arc<Mutex<GitHubModel>>,
}

impl FakeGitHub {
    /// Start the fake for one repo. `installation_id` parameterises the
    /// mint route so the minter under test hits the same id it was
    /// configured with.
    pub(crate) async fn start(owner: &str, name: &str, installation_id: u64) -> Self {
        let server = MockServer::start().await;
        let model = Arc::new(Mutex::new(GitHubModel::new()));

        let blobs_path = format!("/repos/{owner}/{name}/git/blobs");
        Mock::given(method("POST"))
            .and(path(blobs_path))
            .respond_with(WithModel(
                Arc::clone(&model),
                |model: &mut GitHubModel, _req: &Request| {
                    let sha = model.mint_sha();
                    model.objects.insert(sha.clone(), ObjectRecord::Blob);
                    ResponseTemplate::new(201).set_body_json(json!({ "sha": sha }))
                },
            ))
            .mount(&server)
            .await;

        let trees_path = format!("/repos/{owner}/{name}/git/trees");
        Mock::given(method("POST"))
            .and(path(trees_path))
            .respond_with(WithModel(
                Arc::clone(&model),
                |model: &mut GitHubModel, _req: &Request| {
                    let sha = model.mint_sha();
                    model.objects.insert(sha.clone(), ObjectRecord::Tree);
                    ResponseTemplate::new(201).set_body_json(json!({ "sha": sha }))
                },
            ))
            .mount(&server)
            .await;

        let commits_path = format!("/repos/{owner}/{name}/git/commits");
        Mock::given(method("POST"))
            .and(path(commits_path))
            .respond_with(WithModel(
                Arc::clone(&model),
                |model: &mut GitHubModel, req: &Request| {
                    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
                        Ok(v) => v,
                        Err(err) => {
                            return ResponseTemplate::new(400)
                                .set_body_json(json!({ "message": format!("bad body: {err}") }));
                        }
                    };
                    let parents: Vec<String> = body["parents"]
                        .as_array()
                        .map(|ps| {
                            ps.iter()
                                .filter_map(|p| p.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let signed = body.get("signature").is_some_and(|s| !s.is_null());
                    let sha = model.mint_sha();
                    model
                        .objects
                        .insert(sha.clone(), ObjectRecord::Commit { parents });
                    let verification = if signed {
                        json!({ "verified": true, "reason": "valid" })
                    } else {
                        json!({ "verified": false, "reason": "unsigned" })
                    };
                    ResponseTemplate::new(201)
                        .set_body_json(json!({ "sha": sha, "verification": verification }))
                },
            ))
            .mount(&server)
            .await;

        let ref_prefix = format!("/repos/{owner}/{name}/git/ref/heads/");
        let ref_prefix_for_get = ref_prefix.clone();
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/repos/{owner}/{name}/git/ref/heads/.+$"
            )))
            .respond_with(WithModel(
                Arc::clone(&model),
                move |model: &mut GitHubModel, req: &Request| {
                    let branch = branch_from_path(req.url.path(), &ref_prefix_for_get).to_string();
                    match model.refs.get(&branch) {
                        Some(sha) => {
                            ResponseTemplate::new(200).set_body_json(ref_body(&branch, sha))
                        }
                        None => ResponseTemplate::new(404)
                            .set_body_json(json!({ "message": "Not Found" })),
                    }
                },
            ))
            .mount(&server)
            .await;

        let refs_prefix = format!("/repos/{owner}/{name}/git/refs/heads/");
        Mock::given(method("PATCH"))
            .and(path_regex(format!(
                "^/repos/{owner}/{name}/git/refs/heads/.+$"
            )))
            .respond_with(WithModel(
                Arc::clone(&model),
                move |model: &mut GitHubModel, req: &Request| {
                    let branch = branch_from_path(req.url.path(), &refs_prefix).to_string();
                    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
                        Ok(v) => v,
                        Err(err) => {
                            return ResponseTemplate::new(400)
                                .set_body_json(json!({ "message": format!("bad body: {err}") }));
                        }
                    };
                    let Some(new_sha) = body["sha"].as_str().map(str::to_string) else {
                        return ResponseTemplate::new(422)
                            .set_body_json(json!({ "message": "sha missing" }));
                    };
                    let force = body["force"].as_bool().unwrap_or(false);
                    let Some(current) = model.refs.get(&branch).cloned() else {
                        return ResponseTemplate::new(422)
                            .set_body_json(json!({ "message": "Reference does not exist" }));
                    };
                    // GitHub's non-forced check: the new tip must descend
                    // from the *current* head. Deliberately not
                    // compare-and-swap — this asymmetry is what lets tests
                    // express the rewind-then-fast-forward TOCTOU.
                    if !force && !model.descends_from(&new_sha, &current) {
                        return ResponseTemplate::new(422)
                            .set_body_json(json!({ "message": "Update is not a fast forward" }));
                    }
                    model.set_ref(&branch, &new_sha);
                    ResponseTemplate::new(200).set_body_json(ref_body(&branch, &new_sha))
                },
            ))
            .mount(&server)
            .await;

        let repo_path = format!("/repos/{owner}/{name}");
        Mock::given(method("GET"))
            .and(path(repo_path))
            .respond_with(WithModel(
                Arc::clone(&model),
                |model: &mut GitHubModel, _req: &Request| {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "default_branch": model.default_branch }))
                },
            ))
            .mount(&server)
            .await;

        let mint_path = format!("/app/installations/{installation_id}/access_tokens");
        let full_name = format!("{owner}/{name}");
        Mock::given(method("POST"))
            .and(path(mint_path))
            .respond_with(WithModel(
                Arc::clone(&model),
                move |_model: &mut GitHubModel, req: &Request| {
                    let body: serde_json::Value =
                        serde_json::from_slice(&req.body).unwrap_or(json!({}));
                    // Echo the requested permissions verbatim: the minter
                    // refuses any drift between requested and returned, so
                    // the echo is the least-magic way to satisfy it.
                    let permissions = body.get("permissions").cloned().unwrap_or(json!({}));
                    ResponseTemplate::new(201).set_body_json(json!({
                        "token": "ghs_fake_installation_token",
                        "expires_at": one_hour_from_now_rfc3339(),
                        "permissions": permissions,
                        "repository_selection": "selected",
                        "repositories": [{ "full_name": full_name }],
                    }))
                },
            ))
            .mount(&server)
            .await;

        Self { server, model }
    }

    pub(crate) fn uri(&self) -> String {
        self.server.uri()
    }

    fn lock(&self) -> MutexGuard<'_, GitHubModel> {
        self.model.lock().expect("GitHubModel poisoned")
    }

    /// Point `branch` at `sha`, seeding `sha` as a parentless commit
    /// if the model has not seen it. This is how real SHAs (the staged
    /// push's `expected_remote_head`) enter the model.
    pub(crate) fn set_ref(&self, branch: &str, sha: &str) {
        self.lock().set_ref(branch, sha);
    }

    /// Teach the model a commit and its parents without touching refs
    /// — for building ancestor chains the rival-actor tests rewind to.
    pub(crate) fn seed_commit(&self, sha: &str, parents: &[&str]) {
        self.lock().objects.insert(
            sha.to_string(),
            ObjectRecord::Commit {
                parents: parents.iter().map(|p| p.to_string()).collect(),
            },
        );
    }

    pub(crate) fn ref_of(&self, branch: &str) -> Option<String> {
        self.lock().refs.get(branch).cloned()
    }

    /// Every value the ref has held, oldest first, including seeds.
    pub(crate) fn ref_history(&self, branch: &str) -> Vec<String> {
        self.lock()
            .ref_history
            .get(branch)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn requests(&self) -> Vec<RequestRecord> {
        self.lock().requests.clone()
    }

    /// The PATCH requests observed, in order — the harness's ground
    /// truth for "did the crashed attempt send a PATCH?".
    pub(crate) fn patch_requests(&self) -> Vec<RequestRecord> {
        self.lock()
            .requests
            .iter()
            .filter(|r| r.method == "PATCH")
            .cloned()
            .collect()
    }
}

fn one_hour_from_now_rfc3339() -> String {
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    expiry
        .replace_nanosecond(0)
        .expect("zero nanosecond is valid")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC datetime formats as RFC 3339")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RepoRef;
    use crate::github_git_db::{
        CommitIdentity, CommitRequest, GitDataClient, GitDataTimeouts, TreeEntry, TreeEntryKind,
    };
    use crate::vm_git::{GitBranchName, GitObjectId};
    use std::str::FromStr;
    use time::macros::datetime;

    fn repo() -> RepoRef {
        RepoRef::from_str("owner/name").unwrap()
    }

    fn client(fake: &FakeGitHub) -> GitDataClient {
        GitDataClient::new(GitDataTimeouts::production(), fake.uri(), "ghs_fake")
    }

    fn ident() -> CommitIdentity {
        CommitIdentity::new(
            "Test",
            "test@example.invalid",
            datetime!(2024-01-15 10:30:45 UTC),
        )
        .unwrap()
    }

    fn oid(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    /// The full upload-and-publish cycle through the *real* client:
    /// blob → tree → commit (child of the seeded head) → PATCH. The
    /// ref advances exactly once past its seed.
    #[tokio::test]
    async fn upload_then_fast_forward_patch_advances_the_ref() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let seed = oid('a');
        fake.set_ref("main", seed.as_str());

        let client = client(&fake);
        let branch = GitBranchName::new("main").unwrap();
        assert_eq!(
            client.get_branch_head(&repo(), &branch).await.unwrap(),
            seed,
        );

        let blob = client.create_blob(&repo(), b"payload").await.unwrap();
        let tree = client
            .create_tree(
                &repo(),
                &[TreeEntry {
                    path: "file".into(),
                    kind: TreeEntryKind::Blob,
                    sha: blob,
                }],
            )
            .await
            .unwrap();
        let identity = ident();
        let commit = client
            .create_commit(
                &repo(),
                &CommitRequest {
                    tree: &tree,
                    parents: std::slice::from_ref(&seed),
                    message: "msg",
                    author: &identity,
                    committer: &identity,
                    signature: None,
                },
            )
            .await
            .unwrap();

        client.update_ref(&repo(), &branch, &commit).await.unwrap();

        assert_eq!(fake.ref_of("main").unwrap(), commit.as_str());
        assert_eq!(
            fake.ref_history("main"),
            vec![seed.as_str().to_string(), commit.as_str().to_string()],
            "seed plus exactly one move",
        );
    }

    /// A PATCH to a commit that does not descend from the current head
    /// must be refused 422 and must not move the ref — this is the
    /// fast-forward semantics the lease-TOCTOU tests rely on.
    #[tokio::test]
    async fn non_descendant_patch_is_refused_and_ref_unmoved() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let seed = oid('a');
        fake.set_ref("main", seed.as_str());
        // A parentless stranger: not a descendant of `seed`.
        let stranger = oid('b');
        fake.seed_commit(stranger.as_str(), &[]);

        let client = client(&fake);
        let branch = GitBranchName::new("main").unwrap();
        let err = client
            .update_ref(&repo(), &branch, &stranger)
            .await
            .expect_err("non-fast-forward must be refused");
        let crate::github_git_db::GitDataError::ApiError { status, .. } = err else {
            panic!("expected ApiError, got {err:?}");
        };
        assert_eq!(status.as_u16(), 422);
        assert_eq!(fake.ref_of("main").unwrap(), seed.as_str());
        assert_eq!(fake.ref_history("main").len(), 1, "seed only, no moves");
    }

    /// The rewind the rival-actor tests perform: a forced `set_ref`
    /// back to an ancestor, after which a fast-forward PATCH from the
    /// *old* baseline still succeeds — GitHub's check is descent from
    /// current, not compare-and-swap.
    #[tokio::test]
    async fn rewound_ref_still_accepts_a_fast_forward_from_the_old_baseline() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let root = oid('a');
        let tip = oid('b');
        fake.seed_commit(root.as_str(), &[]);
        fake.seed_commit(tip.as_str(), &[root.as_str()]);
        fake.set_ref("main", tip.as_str());
        // Rival rewinds to the ancestor.
        fake.set_ref("main", root.as_str());

        // A new commit built on `tip` (the pre-rewind baseline)…
        let child = oid('c');
        fake.seed_commit(child.as_str(), &[tip.as_str()]);
        // …fast-forwards from `root` because it descends through `tip`.
        let client = client(&fake);
        let branch = GitBranchName::new("main").unwrap();
        client.update_ref(&repo(), &branch, &child).await.unwrap();
        assert_eq!(fake.ref_of("main").unwrap(), child.as_str());
    }

    /// Signed commit creates carry the affirmative verification block
    /// the real contract demands; the real client accepts them
    /// end-to-end. Unsigned creates get `reason: "unsigned"`.
    #[tokio::test]
    async fn signed_commit_create_is_verified_end_to_end() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let client = client(&fake);
        let identity = ident();
        let tree = oid('d');
        let signed = client
            .create_commit(
                &repo(),
                &CommitRequest {
                    tree: &tree,
                    parents: &[],
                    message: "msg",
                    author: &identity,
                    committer: &identity,
                    signature: Some(
                        "-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n",
                    ),
                },
            )
            .await
            .expect("the fake must affirm signed commits");
        // The model knows the commit it minted.
        assert!(fake.lock().objects.contains_key(signed.as_str()));
    }

    /// The request log is the harness's PATCH ground truth: serials
    /// strictly increase and PATCHes are classified.
    #[tokio::test]
    async fn request_log_orders_and_classifies_patches() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let seed = oid('a');
        fake.set_ref("main", seed.as_str());
        let client = client(&fake);
        let branch = GitBranchName::new("main").unwrap();

        let _ = client.get_branch_head(&repo(), &branch).await.unwrap();
        let _ = client.create_blob(&repo(), b"x").await.unwrap();
        client.update_ref(&repo(), &branch, &seed).await.unwrap();

        let requests = fake.requests();
        assert_eq!(requests.len(), 3);
        assert!(
            requests.windows(2).all(|w| w[0].serial + 1 == w[1].serial),
            "serials must strictly increase: {requests:?}",
        );
        let patches = fake.patch_requests();
        assert_eq!(patches.len(), 1);
        assert!(patches[0].path.ends_with("/git/refs/heads/main"));
    }

    /// The mint endpoint echoes the requested permissions and answers
    /// with the configured repo — the shape the real minter's echo
    /// checks demand.
    #[tokio::test]
    async fn mint_endpoint_echoes_permissions_and_repo() {
        let fake = FakeGitHub::start("owner", "name", 999).await;
        let resp = reqwest::Client::new()
            .post(format!(
                "{}/app/installations/999/access_tokens",
                fake.uri()
            ))
            .json(&json!({
                "repositories": ["name"],
                "permissions": { "contents": "write", "metadata": "read" },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["permissions"],
            json!({ "contents": "write", "metadata": "read" }),
        );
        assert_eq!(body["repositories"][0]["full_name"], "owner/name");
        assert_eq!(body["repository_selection"], "selected");
        assert!(!body["token"].as_str().unwrap().is_empty());
    }
}
