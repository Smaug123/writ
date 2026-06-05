//! Flake-input provisioning: serves the per-session VM-facing
//! `POST /v1/nix/flake/provision` endpoint.
//!
//! The guest sends only `(repo, rev)` coordinates — never flake content. The
//! broker re-derives the checkout from its own retained bare mirror (the
//! `(repo, rev)` cache the clone handler populates), runs `nix flake archive`
//! against the committed, locked inputs, and merges them into the shared
//! content-addressed cache the nix-cache endpoint already serves local-first.
//! The guest then realises those inputs through the substituter it already
//! trusts, so `nix develop` evaluates the locked flake without contacting
//! github — preserving the no-egress trust model.
//!
//! The heavy lifting (mirror lookup, materialise, `nix flake archive`, audit)
//! lives in [`crate::flake_provision_from_mirror`]; this module owns only the
//! HTTP shell: request parsing, session preflight, and mapping outcomes and
//! errors onto VM-safe responses.

use std::sync::Arc;

use crate::core::{CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef};
use crate::flake_lock::{FlakeLockError, FlakeProvisionPlanError};
use crate::flake_provision::FlakeProvisionError;
use crate::flake_provision_from_mirror::{
    MirrorFlakeProvisionConfig, MirrorFlakeProvisionError, MirrorFlakeProvisionOutcome,
    provision_flake_from_cached_mirror,
};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::{
    VM_FLAKE_PROVISION_PATH, VmFlakeProvisionErrorCode, VmFlakeProvisionErrorResponse,
    VmFlakeProvisionRequest, VmFlakeProvisionResponse,
};
use crate::vm_git_mirror_cache::{GitCommitSha, MirrorCache};

use super::{VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

/// The host paths, bounds, and caches a session needs to provision flake
/// inputs from a retained mirror. The `mirror_cache` is the same `(repo, rev)`
/// store the clone handler retains into; the provisioning config's cache dir is
/// the same shared CA cache the nix-cache endpoint serves local-first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpFlakeProvisionConfig {
    provision: MirrorFlakeProvisionConfig,
    mirror_cache: MirrorCache,
}

impl VmHttpFlakeProvisionConfig {
    pub fn new(provision: MirrorFlakeProvisionConfig, mirror_cache: MirrorCache) -> Self {
        Self {
            provision,
            mirror_cache,
        }
    }
}

pub struct VmHttpFlakeProvisionService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpFlakeProvisionConfig,
}

impl<S: SecretStore> VmHttpFlakeProvisionService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>, config: VmHttpFlakeProvisionConfig) -> Self {
        Self {
            broker_state,
            config,
        }
    }
}

impl<S: SecretStore> Clone for VmHttpFlakeProvisionService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
        }
    }
}

pub(super) fn is_flake_provision_target(target: &str) -> bool {
    target == VM_FLAKE_PROVISION_PATH
}

pub(super) async fn route_flake_provision_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: VmHttpFlakeProvisionService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    }
    handle_flake_provision_request(session, &body, service).await
}

async fn handle_flake_provision_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    body: &[u8],
    service: VmHttpFlakeProvisionService<S>,
) -> VmHttpResponse {
    let request = match serde_json::from_slice::<VmFlakeProvisionRequest>(body) {
        Ok(request) => request,
        Err(err) => {
            return error_response(
                VmHttpStatus::BadRequest,
                VmFlakeProvisionErrorCode::InvalidRequest,
                format!("invalid flake provision request: {err}"),
            );
        }
    };

    // Preflight the session so a closed/unknown session returns a clean client
    // error before any git or nix work. The authoritative check is the audit
    // request write inside the provisioner, which refuses a closed session;
    // this preflight only spares the materialise + lock read for the common
    // "session is gone" case and yields a precise status.
    if let Err(response) = preflight_session(session, &service) {
        return response;
    }

    let repo = request.repo().as_repo_ref().clone();

    // Authorize the repository against this session's own recorded grants. The
    // retained mirror cache is shared across sessions and can hold private
    // repos cloned by *other* sessions, so an open session is not enough: a
    // session may only provision a repo it was itself granted contents-read on
    // — i.e. one it cloned in this session. `policy::decide` grants read on any
    // repo (the real read gate is the mint, scoped to the session's GitHub App
    // installation), so reusing the recorded clone grant is what fences
    // cross-session access here, and it mints nothing and adds no egress.
    if let Err(response) = authorize_repo(session, &service, &repo) {
        return response;
    }

    // The wire `rev` is a validated 40-hex object id; `GitCommitSha::parse`
    // re-checks the (40|64)-hex commit shape the mirror key requires.
    let rev = match GitCommitSha::parse(request.rev().as_str()) {
        Ok(rev) => rev,
        Err(err) => {
            return error_response(
                VmHttpStatus::BadRequest,
                VmFlakeProvisionErrorCode::InvalidRequest,
                format!("invalid flake provision rev: {err}"),
            );
        }
    };

    let outcome = provision_flake_from_cached_mirror(
        &service.config.provision,
        &service.config.mirror_cache,
        &repo,
        &rev,
        &service.broker_state.audit,
        session.session_id(),
    )
    .await;

    match outcome {
        Ok(MirrorFlakeProvisionOutcome::Provisioned(report)) => VmHttpResponse::json(
            VmHttpStatus::Ok,
            &VmFlakeProvisionResponse::Provisioned {
                request_id: report.request_id(),
                input_count: report.input_count() as u64,
                archived_path_count: report.archived_path_count(),
                archived_bytes: report.archived_bytes(),
            },
        ),
        Ok(MirrorFlakeProvisionOutcome::MirrorNotCached) => {
            VmHttpResponse::json(VmHttpStatus::Ok, &VmFlakeProvisionResponse::MirrorNotCached)
        }
        Err(err) => provision_error_response(&err),
    }
}

/// Verify the session exists and is open. Returns a clean client error
/// otherwise; an audit read failure is reported as an internal error so the
/// guest never proceeds on an unverifiable session.
fn preflight_session<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    service: &VmHttpFlakeProvisionService<S>,
) -> Result<(), VmHttpResponse> {
    match service.broker_state.audit.get_session(session.session_id()) {
        Ok(None) => Err(error_response(
            VmHttpStatus::Unauthorized,
            VmFlakeProvisionErrorCode::Denied,
            "session is not active",
        )),
        Ok(Some(record)) if record.closed_at.is_some() => Err(error_response(
            VmHttpStatus::Gone,
            VmFlakeProvisionErrorCode::Denied,
            "session is closed",
        )),
        Ok(Some(_)) => Ok(()),
        Err(err) => {
            tracing::warn!(error = %err, "vm http flake provision session preflight failed");
            Err(error_response(
                VmHttpStatus::InternalServerError,
                VmFlakeProvisionErrorCode::ProvisionFailed,
                "session preflight failed",
            ))
        }
    }
}

/// Require that this session holds a contents-read grant for `repo`. Returns a
/// `403` otherwise — the caller is authenticated but never proved it may read
/// this repository, so it cannot drive provisioning of another session's
/// cached private mirror. An audit read failure is an internal error so the
/// guest never provisions on an unverifiable authorization.
fn authorize_repo<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    service: &VmHttpFlakeProvisionService<S>,
    repo: &RepoRef,
) -> Result<(), VmHttpResponse> {
    let read_request = CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Read,
        repo: repo.clone(),
    });
    match service
        .broker_state
        .audit
        .session_holds_grant_authorising(session.session_id(), &read_request)
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(error_response(
            VmHttpStatus::Forbidden,
            VmFlakeProvisionErrorCode::Denied,
            "session has no contents-read grant for this repository",
        )),
        Err(err) => {
            tracing::warn!(error = %err, "vm http flake provision authorization check failed");
            Err(error_response(
                VmHttpStatus::InternalServerError,
                VmFlakeProvisionErrorCode::ProvisionFailed,
                "authorization check failed",
            ))
        }
    }
}

/// Map a provision failure onto a VM-safe response. A repository whose
/// committed lock cannot be auto-provisioned (missing lock, or an input the
/// classifier refuses) is reported as [`VmFlakeProvisionErrorCode::Unprovisionable`]
/// with a message drawn from the lock itself — repo content, not host state.
/// Every other failure (git, nix, I/O, audit) is a host-side
/// [`VmFlakeProvisionErrorCode::ProvisionFailed`] whose detail is logged but
/// never returned, so the response cannot leak host paths.
fn provision_error_response(err: &MirrorFlakeProvisionError) -> VmHttpResponse {
    match err {
        MirrorFlakeProvisionError::Provision(provision_err) => {
            provision_inner_error_response(provision_err)
        }
        MirrorFlakeProvisionError::Materialize(materialize_err) => {
            tracing::warn!(error = %materialize_err, "vm http flake provision: materialise failed");
            provision_failed()
        }
    }
}

fn provision_inner_error_response(err: &FlakeProvisionError) -> VmHttpResponse {
    match err {
        // A missing committed lock is a property of the repository, not a host
        // fault: surface it plainly so the guest degrades rather than retrying.
        FlakeProvisionError::ReadLock { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            error_response(
                VmHttpStatus::UnprocessableContent,
                VmFlakeProvisionErrorCode::Unprovisionable,
                "the repository has no committed flake.lock",
            )
        }
        // A lock the classifier refuses (local, private, credential-requiring,
        // or unpinned input). The `FlakeLockError` message describes the lock
        // content and carries no host paths, so it is safe to return.
        FlakeProvisionError::ParseLock(lock_err) => unprovisionable_lock(lock_err),
        FlakeProvisionError::Plan(FlakeProvisionPlanError::Lock(lock_err)) => {
            unprovisionable_lock(lock_err)
        }
        other => {
            tracing::warn!(error = %other, "vm http flake provision failed");
            provision_failed()
        }
    }
}

fn unprovisionable_lock(err: &FlakeLockError) -> VmHttpResponse {
    error_response(
        VmHttpStatus::UnprocessableContent,
        VmFlakeProvisionErrorCode::Unprovisionable,
        format!("repository flake.lock cannot be provisioned: {err}"),
    )
}

fn provision_failed() -> VmHttpResponse {
    error_response(
        VmHttpStatus::InternalServerError,
        VmFlakeProvisionErrorCode::ProvisionFailed,
        "flake input provisioning failed",
    )
}

fn error_response(
    status: VmHttpStatus,
    error: VmFlakeProvisionErrorCode,
    message: impl Into<String>,
) -> VmHttpResponse {
    VmHttpResponse::json(status, &VmFlakeProvisionErrorResponse::new(error, message))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::time::Duration;

    use wiremock::MockServer;

    use super::super::tests::{
        bearer, make_broker_state, open_audit_session, record_contents_read_grant,
        session_for_subnet, token,
    };
    use super::super::{VmHttpRequest, VmHttpServices, route_authenticated_vm_http_request};
    use super::*;
    use crate::core::{Ipv4Cidr, RepoRef, UnixMillis};
    use crate::flake_lock::{FlakeLockError, FlakeProvisionBounds};
    use crate::flake_materialize::MaterializeError;
    use crate::secret::SecretStore;
    use crate::vm_git::GitCloneRepo;

    type TestState = std::sync::Arc<crate::server::BrokerState<Box<dyn SecretStore>>>;

    const TEST_REV: &str = "0123456789abcdef0123456789abcdef01234567";

    fn provision_service_for_test(
        state: &TestState,
        root: &std::path::Path,
    ) -> VmHttpFlakeProvisionService<Box<dyn SecretStore>> {
        // The git/nix programs are never spawned in these tests: every path
        // either short-circuits before tool use (cache miss) or fails earlier
        // (parse, preflight). FK3c-b2 already proves the real git+nix run.
        let provision = MirrorFlakeProvisionConfig::new(
            PathBuf::from("git"),
            PathBuf::from("nix"),
            root.join("materialize"),
            root.join("flake-input-cache"),
            FlakeProvisionBounds::new(64, 1 << 30, Duration::from_secs(120)).unwrap(),
            Duration::from_secs(120),
        );
        let config =
            VmHttpFlakeProvisionConfig::new(provision, MirrorCache::new(root.join("mirror-cache")));
        VmHttpFlakeProvisionService::new(std::sync::Arc::clone(state), config)
    }

    fn provision_request_body(owner: &str, name: &str, rev: &str) -> Vec<u8> {
        let repo = GitCloneRepo::new(repo_ref(owner, name)).unwrap();
        serde_json::to_vec(&VmFlakeProvisionRequest::new(repo, rev.parse().unwrap())).unwrap()
    }

    fn repo_ref(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn session() -> VmHttpSession {
        session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap())
    }

    fn no_flake_provision_services() -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices::none()
    }

    #[tokio::test]
    async fn non_post_method_is_not_found() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        let temp = tempfile::tempdir().unwrap();
        let service = provision_service_for_test(&state, temp.path());
        let request = VmHttpRequest::new(
            "GET",
            VM_FLAKE_PROVISION_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let response = route_flake_provision_request(&session, &request, Vec::new(), service).await;

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn malformed_json_is_bad_request_without_touching_the_session() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        // Session is never opened: malformed JSON is rejected before preflight.
        let session = session();
        let temp = tempfile::tempdir().unwrap();
        let service = provision_service_for_test(&state, temp.path());

        let response = handle_flake_provision_request(&session, b"{not json", service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn unknown_session_is_denied() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        let temp = tempfile::tempdir().unwrap();
        let service = provision_service_for_test(&state, temp.path());
        let body = provision_request_body("o", "n", TEST_REV);

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::Denied);
        assert_eq!(body.message(), "session is not active");
    }

    #[tokio::test]
    async fn closed_session_is_gone() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service = provision_service_for_test(&state, temp.path());
        let body = provision_request_body("o", "n", TEST_REV);

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::Gone);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::Denied);
        assert_eq!(body.message(), "session is closed");
    }

    #[tokio::test]
    async fn cache_miss_returns_mirror_not_cached_without_running_tools() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        record_contents_read_grant(&state, session.session_id(), repo_ref("o", "n"));
        let temp = tempfile::tempdir().unwrap();
        // The mirror cache is empty, so the provisioner short-circuits before
        // any git/nix work and reports the miss as a successful outcome.
        let service = provision_service_for_test(&state, temp.path());
        let body = provision_request_body("o", "n", TEST_REV);

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let parsed: VmFlakeProvisionResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed, VmFlakeProvisionResponse::MirrorNotCached);
        // The miss is not audited as a provision request: nothing was fetched.
        assert!(
            state
                .audit
                .list_flake_provision_requests_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn repo_without_a_session_grant_is_forbidden() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        // The session was granted read on "o/n" (it cloned it), but now asks to
        // provision a *different* repo it never cloned — the cross-session
        // mirror-cache bypass this gate exists to stop.
        record_contents_read_grant(&state, session.session_id(), repo_ref("o", "n"));
        let temp = tempfile::tempdir().unwrap();
        let service = provision_service_for_test(&state, temp.path());
        let body = provision_request_body("other", "repo", TEST_REV);

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let parsed: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmFlakeProvisionErrorCode::Denied);
        // Denied before any provisioning was attempted.
        assert!(
            state
                .audit
                .list_flake_provision_requests_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn disabled_route_is_not_found_for_post() {
        let session = session();
        let request = VmHttpRequest::new(
            "POST",
            VM_FLAKE_PROVISION_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            no_flake_provision_services(),
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[test]
    fn missing_lock_maps_to_unprovisionable() {
        let err = MirrorFlakeProvisionError::Provision(FlakeProvisionError::ReadLock {
            path: PathBuf::from("/broker/scratch/flake-abcdef/flake.lock"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        });

        let response = provision_error_response(&err);

        assert_eq!(response.status, VmHttpStatus::UnprocessableContent);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::Unprovisionable);
        assert_eq!(body.message(), "the repository has no committed flake.lock");
        // The host scratch path the error carried must not reach the guest.
        assert!(!body.message().contains("/broker/scratch"));
    }

    #[test]
    fn refused_lock_surfaces_lock_reason_as_unprovisionable() {
        let err = MirrorFlakeProvisionError::Provision(FlakeProvisionError::ParseLock(
            FlakeLockError::InputRequiresCredentials {
                node: "private-dep".into(),
                reason: "ssh transport".into(),
            },
        ));

        let response = provision_error_response(&err);

        assert_eq!(response.status, VmHttpStatus::UnprocessableContent);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::Unprovisionable);
        assert!(body.message().contains("private-dep"), "{}", body.message());
        assert!(
            body.message().contains("ssh transport"),
            "{}",
            body.message()
        );
    }

    #[test]
    fn host_failures_do_not_leak_detail() {
        // A nix-side failure and a materialise failure both carry host-side
        // detail (paths, stderr); the response must be a generic provision
        // failure that leaks neither.
        let nix_err = MirrorFlakeProvisionError::Provision(FlakeProvisionError::Supervise(
            "nix flake archive: /broker/secret/path exploded".into(),
        ));
        let materialise_err = MirrorFlakeProvisionError::Materialize(MaterializeError::Checkout {
            rev: TEST_REV.into(),
            message: "fatal: /broker/scratch/flake-xyz is corrupt".into(),
        });

        for err in [nix_err, materialise_err] {
            let response = provision_error_response(&err);
            assert_eq!(response.status, VmHttpStatus::InternalServerError);
            let body: VmFlakeProvisionErrorResponse =
                serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body.error(), VmFlakeProvisionErrorCode::ProvisionFailed);
            assert_eq!(body.message(), "flake input provisioning failed");
            assert!(!body.message().contains("/broker"), "{}", body.message());
        }
    }
}
