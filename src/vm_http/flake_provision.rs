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
//! The heavy lifting (mirror lookup, materialise, `nix flake archive`) lives in
//! [`crate::flake_provision_from_mirror`]; this module owns the HTTP shell —
//! request parsing, session preflight, grant re-check — and drives the admitted
//! run through the [`broker_effect`] guard, which owns the audit pair.

use std::sync::Arc;

use crate::audit::{
    AuditError, FlakeProvisionAuditTable, FlakeProvisionOutcomeRecord, FlakeProvisionRequestRecord,
};
use crate::core::{
    CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, RequestId, SessionId, UnixMillis,
};
use crate::flake_lock::{FlakeLockError, FlakeProvisionPlanError};
use crate::flake_provision::{FlakeProvisionError, PerformedFlakeProvision};
use crate::flake_provision_from_mirror::{
    AdmittedMirrorFlakeProvision, MirrorFlakeProvisionAdmission, MirrorFlakeProvisionConfig,
    MirrorFlakeProvisionError, admit_flake_provision_from_cached_mirror,
};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::{
    VM_FLAKE_PROVISION_PATH, VmFlakeProvisionErrorCode, VmFlakeProvisionErrorResponse,
    VmFlakeProvisionRequest, VmFlakeProvisionResponse,
};
use crate::vm_git_mirror_cache::{GitCommitSha, MirrorCache};

use super::broker_effect::{BrokeredEffect, EffectCompletion, broker_effect};
use super::{VmHttpDispatch, VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

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
) -> VmHttpDispatch {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
    }
    handle_flake_provision_dispatch(session, &body, service).await
}

/// Drive a provisioning request through the `broker_effect` guard: everything
/// that can refuse *without attempting an effect* runs first
/// ([`FlakeProvisionEffect::admit`]), and only an admitted run reaches the
/// driver, which begins the request row, runs `nix flake archive`, and completes
/// the outcome row.
async fn handle_flake_provision_dispatch<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    body: &[u8],
    service: VmHttpFlakeProvisionService<S>,
) -> VmHttpDispatch {
    match FlakeProvisionEffect::admit(session, body, &service).await {
        // Answered without beginning an audit row: nothing was fetched, so
        // there is no attempt to record.
        FlakeProvisionAdmission::Answered(response) => response.into(),
        FlakeProvisionAdmission::Admitted(effect) => {
            broker_effect(&service.broker_state.audit, effect).await
        }
    }
}

/// Test-only wrapper returning the buffered response directly — a provisioning
/// response never streams — so the example-based tests read the
/// [`VmHttpResponse`] unchanged.
#[cfg(test)]
async fn handle_flake_provision_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    body: &[u8],
    service: VmHttpFlakeProvisionService<S>,
) -> VmHttpResponse {
    handle_flake_provision_dispatch(session, body, service)
        .await
        .into_buffered()
}

/// The outcome of pre-flighting a request: either an admitted effect for the
/// driver, or a response given *without* beginning an audit row.
enum FlakeProvisionAdmission {
    Admitted(FlakeProvisionEffect),
    /// A client error, a cache miss, or a repository whose committed lock the
    /// classifier refuses. None of these attempted an effect, so none is
    /// audited — the reject-before-begin path.
    Answered(VmHttpResponse),
}

/// An admitted provisioning run modelled as a [`BrokeredEffect`]. The driver
/// owns the audit sequencing, so the `nix flake archive` run cannot reach the
/// host without its `(request, outcome)` pair being recorded.
///
/// It borrows nothing: admission bakes the plan, the materialised checkout, and
/// the derived request-row fields into the effect, so neither the service nor
/// its `SecretStore` parameter appears here.
struct FlakeProvisionEffect {
    request_id: RequestId,
    session_id: SessionId,
    received_at: UnixMillis,
    /// Owned because the request row borrows them as `&str`; both are the
    /// `to_string_lossy` of the admitted plan's paths.
    flake_dir: String,
    cache_dir: String,
    input_count: u64,
    admitted: AdmittedMirrorFlakeProvision,
}

/// Owned outcome payload for a provisioning effect;
/// [`BrokeredEffect::outcome_row`] borrows a [`FlakeProvisionOutcomeRecord`] out
/// of it. Every run produces one — success or failure — so this effect never
/// abandons its guard.
struct FlakeProvisionOutcomeData {
    request_id: RequestId,
    performed: PerformedFlakeProvision,
}

impl FlakeProvisionEffect {
    /// Parse and preflight *before* any audit row is begun: a malformed body,
    /// a closed session, a repository this session was never granted, a
    /// mirror-cache miss, or a lock the classifier refuses all answer here and
    /// record nothing. Only an admitted run is returned.
    async fn admit<S: SecretStore + Send + Sync>(
        session: &VmHttpSession,
        body: &[u8],
        service: &VmHttpFlakeProvisionService<S>,
    ) -> FlakeProvisionAdmission {
        let request = match serde_json::from_slice::<VmFlakeProvisionRequest>(body) {
            Ok(request) => request,
            Err(err) => {
                return FlakeProvisionAdmission::Answered(error_response(
                    VmHttpStatus::BadRequest,
                    VmFlakeProvisionErrorCode::InvalidRequest,
                    format!("invalid flake provision request: {err}"),
                ));
            }
        };

        // Preflight the session so a closed/unknown session returns a clean
        // client error before any git or nix work. The authoritative check is
        // the driver's `begin_effect`, which refuses a closed session; this
        // preflight only spares the materialise + lock read for the common
        // "session is gone" case and yields a precise status.
        if let Err(response) = preflight_session(session, service) {
            return FlakeProvisionAdmission::Answered(response);
        }

        let repo = request.repo().as_repo_ref().clone();

        // Authorize the repository against this session's own recorded grants.
        // The retained mirror cache is shared across sessions and can hold
        // private repos cloned by *other* sessions, so an open session is not
        // enough: a session may only provision a repo it was itself granted
        // contents-read on — i.e. one it cloned in this session.
        // `policy::decide` grants read on any repo (the real read gate is the
        // mint, scoped to the session's GitHub App installation), so reusing the
        // recorded clone grant is what fences cross-session access here, and it
        // mints nothing and adds no egress.
        if let Err(response) = authorize_repo(session, service, &repo) {
            return FlakeProvisionAdmission::Answered(response);
        }

        // The wire `rev` is a validated 40-hex object id; `GitCommitSha::parse`
        // re-checks the (40|64)-hex commit shape the mirror key requires.
        let rev = match GitCommitSha::parse(request.rev().as_str()) {
            Ok(rev) => rev,
            Err(err) => {
                return FlakeProvisionAdmission::Answered(error_response(
                    VmHttpStatus::BadRequest,
                    VmFlakeProvisionErrorCode::InvalidRequest,
                    format!("invalid flake provision rev: {err}"),
                ));
            }
        };

        let admitted = match admit_flake_provision_from_cached_mirror(
            &service.config.provision,
            &service.config.mirror_cache,
            &service.broker_state.mirror_pins,
            &repo,
            &rev,
        )
        .await
        {
            Ok(MirrorFlakeProvisionAdmission::Admitted(admitted)) => admitted,
            Ok(MirrorFlakeProvisionAdmission::MirrorNotCached) => {
                return FlakeProvisionAdmission::Answered(VmHttpResponse::json(
                    VmHttpStatus::Ok,
                    &VmFlakeProvisionResponse::MirrorNotCached,
                ));
            }
            Err(err) => {
                return FlakeProvisionAdmission::Answered(provision_error_response(&err));
            }
        };

        let plan = admitted.admitted();
        FlakeProvisionAdmission::Admitted(FlakeProvisionEffect {
            request_id: plan.request_id(),
            session_id: session.session_id(),
            received_at: UnixMillis::now(),
            flake_dir: plan.flake_dir().to_string_lossy().into_owned(),
            cache_dir: plan.cache_dir().to_string_lossy().into_owned(),
            input_count: plan.input_count() as u64,
            admitted,
        })
    }
}

impl BrokeredEffect for FlakeProvisionEffect {
    type Table = FlakeProvisionAuditTable;
    type Outcome = FlakeProvisionOutcomeData;
    const REQUEST_AUDIT_KIND: &'static str = "flake_provision_request";
    const OUTCOME_AUDIT_KIND: &'static str = "flake_provision_outcome";

    fn audit_key(&self) -> impl std::fmt::Display + '_ {
        self.request_id
    }

    fn request_row(&self) -> FlakeProvisionRequestRecord<'_> {
        FlakeProvisionRequestRecord {
            request_id: self.request_id,
            session_id: self.session_id,
            received_at: self.received_at,
            flake_dir: &self.flake_dir,
            cache_dir: &self.cache_dir,
            input_count: self.input_count,
        }
    }

    async fn perform(self) -> EffectCompletion<Self> {
        let request_id = self.request_id;
        let performed = self.admitted.run().await;
        let response = match &performed {
            PerformedFlakeProvision::Provisioned(report) => VmHttpResponse::json(
                VmHttpStatus::Ok,
                &VmFlakeProvisionResponse::Provisioned {
                    request_id: report.request_id(),
                    input_count: report.input_count() as u64,
                    archived_path_count: report.archived_path_count(),
                    archived_bytes: report.archived_bytes().get(),
                },
            ),
            // A run that started and failed is a host fault, never a lock
            // refusal (the classifier ran at admission), so this always maps to
            // a detail-free `ProvisionFailed`.
            PerformedFlakeProvision::Failed { error, .. } => provision_inner_error_response(error),
        };
        EffectCompletion::Buffered {
            outcome: FlakeProvisionOutcomeData {
                request_id,
                performed,
            },
            response,
        }
    }

    fn outcome_row(outcome: &FlakeProvisionOutcomeData) -> FlakeProvisionOutcomeRecord<'_> {
        FlakeProvisionOutcomeRecord {
            request_id: outcome.request_id,
            completed_at: UnixMillis::now(),
            result: outcome.performed.audit_result(),
        }
    }

    fn begin_error_response(err: &AuditError) -> Option<VmHttpResponse> {
        // The session closed between the preflight above and the request row: a
        // clean client error with the same status the preflight would have
        // given, not an audit-write failure.
        match err {
            AuditError::Invariant("session does not exist") => Some(error_response(
                VmHttpStatus::Unauthorized,
                VmFlakeProvisionErrorCode::Denied,
                "session is not active",
            )),
            AuditError::Invariant("session is closed") => Some(error_response(
                VmHttpStatus::Gone,
                VmFlakeProvisionErrorCode::Denied,
                "session is closed",
            )),
            _ => None,
        }
    }

    fn audit_write_failure_response() -> VmHttpResponse {
        // Preserve the typed envelope in the audit-fault mode: the endpoint
        // always answered a JSON `VmFlakeProvisionErrorResponse`, so an audit
        // write failure keeps that contract rather than the driver's plain-text
        // 500.
        provision_failed()
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
    use writ_core::byte_size::ByteSize;

    use wiremock::MockServer;

    use super::super::tests::{
        bearer, make_broker_state, open_audit_session, record_contents_read_grant,
        session_for_subnet, token,
    };
    use super::super::{
        VmHttpRequest, VmHttpServices, resolve_and_route_authenticated_vm_http_request,
    };
    use super::*;
    use crate::audit::FlakeProvisionAuditOutcome;
    use crate::core::{Ipv4Cidr, RepoRef, UnixMillis};
    use crate::flake_fixtures::{
        NO_INPUT_LOCK, SSH_INPUT_LOCK, fake_nix_archiving, fake_nix_failing,
        flake_mirror_with_lock, tool_on_path,
    };
    use crate::flake_lock::{FlakeLockError, FlakeProvisionBounds};
    use crate::flake_materialize::MaterializeError;
    use crate::secret::SecretStore;
    use crate::vm_git::GitCloneRepo;
    use crate::vm_git_mirror_cache::MirrorCacheKey;

    type TestState = std::sync::Arc<crate::server::BrokerState<Box<dyn SecretStore>>>;

    const TEST_REV: &str = "0123456789abcdef0123456789abcdef01234567";

    fn provision_service_for_test(
        state: &TestState,
        root: &std::path::Path,
    ) -> VmHttpFlakeProvisionService<Box<dyn SecretStore>> {
        // The git/nix programs are never spawned in these tests: every path
        // either short-circuits before tool use (cache miss) or fails earlier
        // (parse, preflight). The tool-running paths use
        // `provision_service_with_tools` below.
        provision_service_with_tools(state, root, PathBuf::from("git"), PathBuf::from("nix"))
    }

    /// A service wired to real/fake tool paths and an empty mirror cache, so a
    /// test can seed the cache and drive the whole endpoint.
    fn provision_service_with_tools(
        state: &TestState,
        root: &std::path::Path,
        git_program: PathBuf,
        nix_program: PathBuf,
    ) -> VmHttpFlakeProvisionService<Box<dyn SecretStore>> {
        let provision = MirrorFlakeProvisionConfig::new(
            git_program,
            nix_program,
            root.join("materialize"),
            root.join("flake-input-cache"),
            FlakeProvisionBounds::new(64, ByteSize::gib(1), Duration::from_secs(120)).unwrap(),
            Duration::from_secs(120),
        );
        let config =
            VmHttpFlakeProvisionConfig::new(provision, MirrorCache::new(root.join("mirror-cache")));
        VmHttpFlakeProvisionService::new(std::sync::Arc::clone(state), config)
    }

    /// Seed the service's mirror cache with a real bare mirror of a repo whose
    /// committed lock is `lock`, as a clone in this session would have. Returns
    /// the `(repo, rev)` the guest then asks to provision.
    fn seed_mirror(
        root: &std::path::Path,
        git_program: &std::path::Path,
        lock: &str,
    ) -> (RepoRef, GitCommitSha) {
        let (mirror, rev) = flake_mirror_with_lock(git_program, &root.join("fixture"), lock);
        let repo = repo_ref("o", "n");
        MirrorCache::new(root.join("mirror-cache"))
            .insert(&MirrorCacheKey::new(&repo, &rev), &mirror)
            .unwrap();
        (repo, rev)
    }

    /// The one flake-provision audit entry this session recorded, asserting the
    /// pair is complete (no `*_request` row without its `*_outcome` partner).
    fn sole_audit_entry(
        state: &TestState,
        session: &VmHttpSession,
    ) -> crate::audit::FlakeProvisionAuditEntry {
        state.audit.assert_effect_audit_pairs_complete(
            "flake_provision_request",
            "flake_provision_outcome",
            "request_id",
        );
        let mut entries = state
            .audit
            .list_flake_provision_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1, "expected exactly one provision request");
        entries.remove(0)
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

        let response = route_flake_provision_request(&session, &request, Vec::new(), service)
            .await
            .into_buffered();

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

        let response = resolve_and_route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            no_flake_provision_services(),
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    /// The audited success path, end to end: a real bare mirror is materialised
    /// and a fake `nix` archives into the staging cache, so the scan, the budget
    /// check, and the cache merge all run. The endpoint must answer
    /// `Provisioned` *and* leave a complete `(request, outcome)` audit pair —
    /// the invariant this whole series exists to make structural.
    #[tokio::test]
    async fn provisioned_flake_records_a_complete_audit_pair() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        let temp = tempfile::tempdir().unwrap();
        let (repo, rev) = seed_mirror(temp.path(), &git_program, NO_INPUT_LOCK);
        record_contents_read_grant(&state, session.session_id(), repo.clone());
        let service = provision_service_with_tools(
            &state,
            temp.path(),
            git_program,
            fake_nix_archiving(temp.path()),
        );
        let body = provision_request_body(&repo.owner, &repo.name, rev.as_str());

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let parsed: VmFlakeProvisionResponse = serde_json::from_slice(&response.body).unwrap();
        let VmFlakeProvisionResponse::Provisioned {
            request_id,
            input_count,
            archived_path_count,
            ..
        } = parsed
        else {
            panic!("a cached, provisionable mirror should provision: {parsed:?}");
        };
        assert_eq!(input_count, 0, "the fixture lock declares no inputs");
        assert_eq!(archived_path_count, 1, "the fake nix archives one path");

        let entry = sole_audit_entry(&state, &session);
        assert_eq!(entry.request_id, request_id);
        assert_eq!(entry.input_count, 0);
        assert!(
            matches!(
                entry.outcome,
                Some(FlakeProvisionAuditOutcome::Success {
                    archived_path_count: 1,
                    ..
                })
            ),
            "got: {:?}",
            entry.outcome
        );
    }

    /// The audited failure path: `nix` runs and exits non-zero. The guest sees a
    /// generic provision failure, and the pair is still complete — a failed
    /// effect is recorded, not dropped.
    #[tokio::test]
    async fn failed_provision_records_a_failure_outcome() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        let temp = tempfile::tempdir().unwrap();
        let (repo, rev) = seed_mirror(temp.path(), &git_program, NO_INPUT_LOCK);
        record_contents_read_grant(&state, session.session_id(), repo.clone());
        let service = provision_service_with_tools(
            &state,
            temp.path(),
            git_program,
            fake_nix_failing(temp.path(), 3),
        );
        let body = provision_request_body(&repo.owner, &repo.name, rev.as_str());

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        let parsed: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmFlakeProvisionErrorCode::ProvisionFailed);
        // The host-side detail stays host-side.
        assert_eq!(parsed.message(), "flake input provisioning failed");

        let entry = sole_audit_entry(&state, &session);
        let Some(FlakeProvisionAuditOutcome::Failure { error }) = entry.outcome else {
            panic!(
                "a non-zero nix exit must audit a failure: {:?}",
                entry.outcome
            );
        };
        assert!(
            error.contains("nix flake archive exited with"),
            "the audit row keeps the detail the guest does not see: {error}"
        );
    }

    /// A lock the classifier refuses is a property of the repository, not an
    /// attempted effect: the guest is told, and *nothing* is audited — the
    /// reject-before-begin path, with real git work having already happened.
    #[tokio::test]
    async fn unprovisionable_lock_is_refused_before_any_audit_row() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session();
        open_audit_session(&state, session.session_id());
        let temp = tempfile::tempdir().unwrap();
        let (repo, rev) = seed_mirror(temp.path(), &git_program, SSH_INPUT_LOCK);
        record_contents_read_grant(&state, session.session_id(), repo.clone());
        // `nix` would fail loudly if it were ever spawned; it must not be.
        let service = provision_service_with_tools(
            &state,
            temp.path(),
            git_program,
            PathBuf::from("/nonexistent/nix"),
        );
        let body = provision_request_body(&repo.owner, &repo.name, rev.as_str());

        let response = handle_flake_provision_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::UnprocessableContent);
        let parsed: VmFlakeProvisionErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmFlakeProvisionErrorCode::Unprovisionable);
        assert!(
            state
                .audit
                .list_flake_provision_requests_for_session(session.session_id())
                .unwrap()
                .is_empty(),
            "a refused lock attempts no effect, so it records none"
        );
    }

    /// A session that closes between the preflight and the driver's request-row
    /// write is still a clean client error — the same status the preflight would
    /// have given — not an audit-write failure. Everything else keeps the
    /// endpoint's typed 500 envelope.
    #[test]
    fn begin_failures_map_sessions_to_client_errors_and_the_rest_to_the_typed_500() {
        let unauthorized = FlakeProvisionEffect::begin_error_response(&AuditError::Invariant(
            "session does not exist",
        ))
        .expect("an unknown session is a client error");
        assert_eq!(unauthorized.status, VmHttpStatus::Unauthorized);

        let gone =
            FlakeProvisionEffect::begin_error_response(&AuditError::Invariant("session is closed"))
                .expect("a closed session is a client error");
        assert_eq!(gone.status, VmHttpStatus::Gone);

        assert!(
            FlakeProvisionEffect::begin_error_response(&AuditError::Invariant("disk on fire"))
                .is_none(),
            "a genuine audit fault must fall through to the audit-write 500"
        );
        let fault = FlakeProvisionEffect::audit_write_failure_response();
        assert_eq!(fault.status, VmHttpStatus::InternalServerError);
        let body: VmFlakeProvisionErrorResponse = serde_json::from_slice(&fault.body).unwrap();
        assert_eq!(body.error(), VmFlakeProvisionErrorCode::ProvisionFailed);
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
