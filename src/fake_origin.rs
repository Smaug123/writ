//! A locally-served git origin for pipeline tests (test-only).
//!
//! `prepare_staging_repo` runs a real `git fetch <url> <sha>` to pull
//! the staged push's prerequisite commit from "GitHub". This module
//! stands that origin up on `127.0.0.1`: a bare repo with a
//! deterministic two-commit chain, served over **git's dumb HTTP
//! protocol** — `git update-server-info` after every mutation plus
//! verbatim static file service of `info/refs` and `objects/**`. Dumb
//! HTTP needs no `http-backend` CGI and no upload-pack configuration;
//! the client walks loose objects by SHA directly, which is exactly
//! the fetch-by-SHA shape the prepare step issues. (If a future git
//! version drops dumb-protocol support, swap the serving strategy
//! behind this same API for a CGI shim — the stage oracle in
//! `git_push_approve` is protocol-independent.)
//!
//! The fixture also produces the matching staged **bundle** (real
//! `git bundle create` of the commits past the prerequisite), so a
//! test holds the full staged-push triple: `expected_remote_head` (the
//! prerequisite), `new_head` (the bundle tip), and the bundle bytes.
//!
//! Repos are built with the same hardened, identity-pinned `git`
//! invocations the walker tests use, so SHAs are deterministic across
//! runs and machines. Callers must skip when `git` is absent (the
//! constructor returns `None`), matching the `maybe_git()` precedent.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Command;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};

use crate::vm_git::GitObjectId;
use crate::vm_git_bundle::GitCloneBaseUrl;
use writ_core::git_env::apply_clean_git_config;

/// The repository identity every fake-origin test uses; matches
/// [`crate::fake_github::FakeGitHub`]'s conventional fixture repo.
pub(crate) const ORIGIN_OWNER: &str = "owner";
pub(crate) const ORIGIN_NAME: &str = "name";

/// A running fake origin plus the staged-push fixture built from it.
pub(crate) struct FakeOrigin {
    /// Owns every repo directory; dropped last.
    _tmp: tempfile::TempDir,
    base_url: String,
    server: tokio::task::JoinHandle<()>,
    prereq: GitObjectId,
    tip: GitObjectId,
    bundle: Vec<u8>,
}

impl Drop for FakeOrigin {
    fn drop(&mut self) {
        // The accept loop holds no state worth flushing; stop serving.
        self.server.abort();
    }
}

impl FakeOrigin {
    /// Build the origin and start serving it. Returns `None` when
    /// `git` is not on `PATH` (callers print a skip note, matching the
    /// suite's convention for real-git tests).
    pub(crate) async fn start() -> Option<Self> {
        let git = maybe_git()?;
        let tmp = tempfile::tempdir().expect("fake origin tempdir");

        // Work repo: base commit (the prerequisite — what "GitHub"
        // already has) plus one feature commit (the staged push).
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).expect("create work dir");
        run_git(&git, &work, &["init", "--quiet", "--initial-branch=main"]);
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "base"],
        );
        let prereq = rev_parse(&git, &work, "HEAD");
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "feature"],
        );
        let tip = rev_parse(&git, &work, "HEAD");

        // The staged bundle: everything past the prerequisite, with
        // the prerequisite recorded as such — the shape a VM push
        // stages.
        let bundle_path = tmp.path().join("staged.bundle");
        run_git(
            &git,
            &work,
            &[
                "bundle",
                "create",
                bundle_path.to_str().expect("tempdir path is UTF-8"),
                &format!("{}..refs/heads/main", prereq.as_str()),
            ],
        );
        let bundle = std::fs::read(&bundle_path).expect("read staged bundle");

        // Bare origin at the dumb-HTTP layout git expects: the branch
        // points at the *prerequisite* (GitHub has not seen the staged
        // commits), and update-server-info writes info/refs.
        let origin = tmp.path().join("origin.git");
        run_git(
            &git,
            tmp.path(),
            &["init", "--bare", "--quiet", "origin.git"],
        );
        run_git(
            &git,
            &origin,
            &[
                "fetch",
                "--no-tags",
                "--quiet",
                work.to_str().expect("tempdir path is UTF-8"),
                &format!("{}:refs/heads/main", prereq.as_str()),
            ],
        );
        run_git(&git, &origin, &["update-server-info"]);

        let (base_url, server) = serve_dumb_http(origin).await;

        Some(Self {
            _tmp: tmp,
            base_url,
            server,
            prereq,
            tip,
            bundle,
        })
    }

    /// The clone base URL to plug into `PromoteRuntimeConfig`; the
    /// origin answers `{base}/owner/name.git/...`.
    pub(crate) fn clone_base_url(&self) -> GitCloneBaseUrl {
        GitCloneBaseUrl::parse(&self.base_url).expect("local base url parses")
    }

    /// The prerequisite commit — the staged receipt's
    /// `expected_remote_head`, and what the origin's branch serves.
    pub(crate) fn prereq(&self) -> &GitObjectId {
        &self.prereq
    }

    /// The bundle tip — the staged receipt's `new_head`.
    pub(crate) fn tip(&self) -> &GitObjectId {
        &self.tip
    }

    pub(crate) fn bundle_bytes(&self) -> &[u8] {
        &self.bundle
    }
}

/// Serve `repo_dir` (a bare repo) as `/{ORIGIN_OWNER}/{ORIGIN_NAME}.git/**`
/// over plain HTTP/1.1 on an ephemeral local port. Static GETs only —
/// the dumb protocol needs nothing else.
async fn serve_dumb_http(repo_dir: PathBuf) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake origin listener");
    let addr = listener.local_addr().expect("fake origin local addr");
    let base_url = format!("http://{addr}/");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let repo_dir = repo_dir.clone();
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let repo_dir = repo_dir.clone();
                    async move { Ok::<_, Infallible>(serve_file(&repo_dir, req.uri().path())) }
                });
                // Connection errors (client hangup mid-fetch) are the
                // client's story to tell; nothing to do here.
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    (base_url, handle)
}

fn serve_file(repo_dir: &Path, url_path: &str) -> Response<Full<Bytes>> {
    let not_found = || {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .expect("static response builds")
    };
    let repo_prefix = format!("/{ORIGIN_OWNER}/{ORIGIN_NAME}.git/");
    let Some(rel) = url_path.strip_prefix(&repo_prefix) else {
        return not_found();
    };
    // The dumb client only requests paths inside the repo; refuse
    // anything that could escape it anyway.
    if rel.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return not_found();
    }
    match std::fs::read(repo_dir.join(rel)) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(Full::new(Bytes::from(bytes)))
            .expect("static response builds"),
        Err(_) => not_found(),
    }
}

/// Locate `git` on `PATH`; `None` means the caller should skip.
pub(crate) fn maybe_git() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("git");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// `git -C <repo> <args>` under the hardened, identity-pinned env the
/// walker tests use; SHAs stay deterministic across runs and machines.
fn run_git(git: &Path, repo: &Path, args: &[&str]) -> std::process::Output {
    let output = apply_clean_git_config(&mut Command::new(git))
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_clear()
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
    let sha = String::from_utf8(out.stdout)
        .expect("rev-parse output is UTF-8")
        .trim()
        .to_string();
    GitObjectId::new(sha).expect("rev-parse output must be a valid 40-hex SHA")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture's own consistency: the bundle tip descends from the
    /// prerequisite, the origin serves `info/refs` naming the
    /// prerequisite, and unknown paths 404.
    #[tokio::test]
    async fn origin_serves_info_refs_for_the_prereq() {
        let Some(origin) = FakeOrigin::start().await else {
            eprintln!("skipping: `git` not on PATH");
            return;
        };
        assert_ne!(origin.prereq(), origin.tip());
        assert!(!origin.bundle_bytes().is_empty());

        let url = format!(
            "{}{}/{}.git/info/refs",
            origin.base_url, ORIGIN_OWNER, ORIGIN_NAME
        );
        let body = reqwest::get(&url).await.unwrap().text().await.unwrap();
        assert!(
            body.contains(origin.prereq().as_str()) && body.contains("refs/heads/main"),
            "info/refs must advertise the prerequisite at refs/heads/main, got: {body}",
        );

        let escape = format!(
            "{}{}/{}.git/../../../etc/passwd",
            origin.base_url, ORIGIN_OWNER, ORIGIN_NAME
        );
        let status = reqwest::Client::new()
            .get(&escape)
            .send()
            .await
            .unwrap()
            .status();
        assert_ne!(status.as_u16(), 200, "traversal must not serve files");
    }
}
