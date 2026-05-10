//! Git clone: serves the per-session VM-facing `POST /v1/git/clone` endpoint
//! by minting a short-lived GitHub installation token, running `git clone`
//! followed by `git bundle create`, and returning the bundle bytes to the
//! guest.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::{CapabilityRequest, GitHubAccess, GitHubRequest};
use crate::secret::SecretStore;
use crate::server::{BrokerState, CapabilityOutcome, request_capability};
use crate::vm_git::{
    GIT_BUNDLE_CONTENT_TYPE, VM_GIT_CLONE_PATH, VmGitCloneErrorCode, VmGitCloneErrorResponse,
    VmGitCloneRequest,
};
use crate::vm_git_bundle::{
    GitCloneBaseUrl, GitCloneBundlePlan, GitCloneBundlePlanError, GitCloneBundleRunError,
    GitCloneBundleSource, GitCredentialBoundary, GitSecretValue, GitSecretValueError,
    run_git_clone_bundle,
};

use super::{VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

pub struct VmHttpGitCloneService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpGitCloneConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpGitCloneConfig {
    git_program: PathBuf,
    clone_base_url: GitCloneBaseUrl,
    credential: GitCredentialBoundary,
    work_root: PathBuf,
    timeout: std::time::Duration,
    max_bundle_bytes: u64,
}

impl<S: SecretStore> VmHttpGitCloneService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>, config: VmHttpGitCloneConfig) -> Self {
        Self {
            broker_state,
            config,
        }
    }
}

impl<S: SecretStore> Clone for VmHttpGitCloneService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
        }
    }
}

impl VmHttpGitCloneConfig {
    pub fn new(
        git_program: impl Into<PathBuf>,
        credential: GitCredentialBoundary,
        work_root: impl Into<PathBuf>,
        timeout: std::time::Duration,
        max_bundle_bytes: u64,
    ) -> Result<Self, GitCloneBundlePlanError> {
        Self::new_with_clone_base_url(
            git_program,
            GitCloneBaseUrl::github(),
            credential,
            work_root,
            timeout,
            max_bundle_bytes,
        )
    }

    pub fn new_with_clone_base_url(
        git_program: impl Into<PathBuf>,
        clone_base_url: GitCloneBaseUrl,
        credential: GitCredentialBoundary,
        work_root: impl Into<PathBuf>,
        timeout: std::time::Duration,
        max_bundle_bytes: u64,
    ) -> Result<Self, GitCloneBundlePlanError> {
        let git_program = git_program.into();
        let work_root = work_root.into();
        if git_program.as_os_str().is_empty() {
            return Err(GitCloneBundlePlanError::EmptyPath {
                field: "git_program",
            });
        }
        if work_root.as_os_str().is_empty() {
            return Err(GitCloneBundlePlanError::EmptyPath { field: "work_root" });
        }
        if !work_root.is_absolute() {
            return Err(GitCloneBundlePlanError::RelativePath {
                field: "work_root",
                path: work_root,
            });
        }
        if timeout.is_zero() {
            return Err(GitCloneBundlePlanError::ZeroTimeout);
        }
        if max_bundle_bytes == 0 {
            return Err(GitCloneBundlePlanError::ZeroMaxBundleBytes);
        }
        Ok(Self {
            git_program,
            clone_base_url,
            credential,
            work_root,
            timeout,
            max_bundle_bytes,
        })
    }

    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    fn plan_for_request(
        &self,
        request: VmGitCloneRequest,
    ) -> Result<GitCloneBundlePlan, GitCloneBundlePlanError> {
        let work_dir = self
            .work_root
            .join(format!("clone-{}", uuid::Uuid::new_v4().simple()));
        let bundle_path = work_dir.join("repo.bundle");
        GitCloneBundlePlan::new_with_source(
            self.git_program.clone(),
            GitCloneBundleSource::new(request, self.clone_base_url.clone()),
            self.credential.clone(),
            work_dir,
            bundle_path,
            self.timeout,
            self.max_bundle_bytes,
        )
    }
}

pub(super) fn is_git_clone_target(target: &str) -> bool {
    target == VM_GIT_CLONE_PATH
}

pub(super) async fn route_git_clone_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: VmHttpGitCloneService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    }
    handle_git_clone_request(session, &body, service).await
}

async fn handle_git_clone_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    body: &[u8],
    service: VmHttpGitCloneService<S>,
) -> VmHttpResponse {
    let request = match serde_json::from_slice::<VmGitCloneRequest>(body) {
        Ok(request) => request,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::BadRequest,
                VmGitCloneErrorCode::InvalidRequest,
                format!("invalid Git clone request: {err}"),
            );
        }
    };

    let capability = git_clone_authorization_request(&request);
    let outcome = request_capability(session.session_id(), capability, &service.broker_state).await;
    let token = match git_clone_token_from_capability_outcome(outcome) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let secret = match GitSecretValue::new(token) {
        Ok(secret) => secret,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                git_secret_error_message(err),
            );
        }
    };
    let plan = match service.config.plan_for_request(request) {
        Ok(plan) => plan,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                format!("invalid Git clone service configuration: {err}"),
            );
        }
    };

    match run_git_clone_bundle_and_read(&plan, &secret).await {
        Ok(bundle) => VmHttpResponse {
            status: VmHttpStatus::Ok,
            content_type: GIT_BUNDLE_CONTENT_TYPE,
            body: bundle,
            content_length: None,
            www_authenticate: None,
            headers: Vec::new(),
        },
        Err(message) => git_error_response(
            VmHttpStatus::InternalServerError,
            VmGitCloneErrorCode::CloneFailed,
            message,
        ),
    }
}

fn git_clone_authorization_request(request: &VmGitCloneRequest) -> CapabilityRequest {
    CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Read,
        repo: request.repo().as_repo_ref().clone(),
    })
}

fn git_clone_token_from_capability_outcome(
    outcome: CapabilityOutcome,
) -> Result<String, VmHttpResponse> {
    match outcome {
        CapabilityOutcome::Granted { token, .. } => Ok(token),
        CapabilityOutcome::Denied { reason } => Err(git_error_response(
            VmHttpStatus::Forbidden,
            VmGitCloneErrorCode::Denied,
            reason,
        )),
        CapabilityOutcome::UnknownSession { .. } => Err(git_error_response(
            VmHttpStatus::Unauthorized,
            VmGitCloneErrorCode::Denied,
            "session is not active",
        )),
        CapabilityOutcome::ClosedSession { .. } => Err(git_error_response(
            VmHttpStatus::Gone,
            VmGitCloneErrorCode::Denied,
            "session is closed",
        )),
        CapabilityOutcome::Error { message } => {
            eprintln!("VM HTTP Git clone credential request failed: {message}");
            Err(git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                "credential request failed",
            ))
        }
    }
}

async fn run_git_clone_bundle_and_read(
    plan: &GitCloneBundlePlan,
    secret: &GitSecretValue,
) -> Result<Vec<u8>, String> {
    prepare_git_work_root(plan.work_dir().parent().ok_or_else(|| {
        format!(
            "Git clone work directory has no parent: {}",
            plan.work_dir().display()
        )
    })?)
    .await?;

    let work_dir = plan.work_dir().to_path_buf();
    let run_result = async {
        run_git_clone_bundle(plan, secret)
            .await
            .map_err(git_clone_run_error_message)?;
        // TODO: stream the bundle into the HTTP response instead of buffering
        // it here once the VM HTTP response type supports streaming bodies.
        tokio::fs::read(plan.bundle_path()).await.map_err(|err| {
            format!(
                "cannot read Git bundle {}: {err}",
                plan.bundle_path().display()
            )
        })
    }
    .await;

    let cleanup_result = match tokio::fs::remove_dir_all(&work_dir).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "cannot remove Git clone work directory {}: {err}",
            work_dir.display()
        )),
    };

    match (run_result, cleanup_result) {
        (Ok(bundle), Ok(())) => Ok(bundle),
        (Ok(_), Err(cleanup)) => Err(format!(
            "Git clone completed but temporary artifacts were not removed: {cleanup}"
        )),
        (Err(original), Ok(())) => Err(original),
        (Err(original), Err(cleanup)) => Err(format!("{original}; additionally, {cleanup}")),
    }
}

async fn prepare_git_work_root(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => validate_git_work_root_metadata(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|err| {
                        format!(
                            "cannot inspect Git clone work root {}: {err}",
                            path.display()
                        )
                    })?;
                    return validate_git_work_root_metadata(path, &metadata);
                }
                Err(err) => {
                    return Err(format!(
                        "cannot create Git clone work root {}: {err}",
                        path.display()
                    ));
                }
            }
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|err| {
                    format!(
                        "cannot set Git clone work root permissions for {}: {err}",
                        path.display()
                    )
                })
        }
        Err(err) => Err(format!(
            "cannot inspect Git clone work root {}: {err}",
            path.display()
        )),
    }
}

fn validate_git_work_root_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if !metadata.is_dir() {
        return Err(format!(
            "Git clone work root is not a directory: {}",
            path.display()
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "Git clone work root {} has group/world access bits (mode {:04o}); \
             use a dedicated 0700 directory",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

fn git_error_response(
    status: VmHttpStatus,
    error: VmGitCloneErrorCode,
    message: impl Into<String>,
) -> VmHttpResponse {
    VmHttpResponse::json(status, &VmGitCloneErrorResponse::new(error, message))
}

fn git_secret_error_message(err: GitSecretValueError) -> String {
    format!("minted Git credential cannot be passed to Git: {err}")
}

fn git_clone_run_error_message(err: GitCloneBundleRunError) -> String {
    format!("Git clone failed: {err}")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::tests::{
        bearer, git_clone_config_for_test, make_broker_state, no_services, open_audit_session,
        required_test_tool, session_for_subnet, shell_single_quote, token, write_fake_git,
        write_fake_git_with_bundle_epilogue,
    };
    use super::super::{
        VM_HTTP_READ_TIMEOUT, VmHttpProxies, VmHttpRequest, VmHttpServices, VmHttpSession,
        VmHttpStatus, bind_ephemeral_vm_http_listener, dispatch_vm_http_head_and_body,
        handle_vm_http_connection_with_read_timeout, route_authenticated_vm_http_request,
        run_vm_http_with_services_until_shutdown,
    };
    use super::*;
    use crate::core::{BrokerPortRange, CapabilityRequest, GitHubAccess, GitHubRequest, Ipv4Cidr};
    use crate::core::{RepoRef, UnixMillis};
    use crate::secret::SecretStore;
    use crate::server::CapabilityOutcome;
    use crate::vm_git::GitCloneRepo;

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn expiry_str_from_now(secs: i64) -> String {
        let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(secs);
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    pub(super) fn git_clone_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        temp: &tempfile::TempDir,
        fake_git: PathBuf,
    ) -> VmHttpGitCloneService<Box<dyn SecretStore>> {
        VmHttpGitCloneService::new(Arc::clone(state), git_clone_config_for_test(temp, fake_git))
    }

    fn services_with_git(
        git_clone: VmHttpGitCloneService<Box<dyn SecretStore>>,
    ) -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices {
            git_clone: Some(git_clone),
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
        }
    }

    async fn request_over_tcp(addr: SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn disabled_git_clone_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));

        for method in ["GET", "POST"] {
            let request = VmHttpRequest::new(
                method,
                VM_GIT_CLONE_PATH,
                Some(bearer(token().as_str())),
                peer,
            );
            let response = route_authenticated_vm_http_request(
                &session,
                &request,
                Vec::new(),
                no_services(),
            )
            .await
            .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_git_clone_route_is_not_found_for_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let request = VmHttpRequest::new(
            "GET",
            VM_GIT_CLONE_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            services_with_git(service),
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[test]
    fn git_clone_capability_denial_maps_to_forbidden_error_response() {
        let response = git_clone_token_from_capability_outcome(CapabilityOutcome::Denied {
            reason: "policy says no".into(),
        })
        .unwrap_err();

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(body.message(), "policy says no");
    }

    #[test]
    fn git_clone_authorization_request_grants_github_contents_read_scope() {
        let request =
            VmGitCloneRequest::new(GitCloneRepo::new(repo("smaug123", "writ")).unwrap(), None);

        match git_clone_authorization_request(&request) {
            CapabilityRequest::GitHub(GitHubRequest::Contents { access, repo }) => {
                assert_eq!(access, GitHubAccess::Read);
                assert_eq!(repo, "smaug123/writ".parse::<RepoRef>().unwrap());
            }
            other => panic!("unexpected capability: {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabled_git_clone_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                "POST",
                VM_GIT_CLONE_PATH,
                &[
                    ("authorization", bearer_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                no_services(),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("disabled Git clone route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn enabled_git_clone_non_post_route_does_not_read_declared_body() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                "GET",
                VM_GIT_CLONE_PATH,
                &[
                    ("authorization", bearer_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                services_with_git(service),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("non-POST Git clone route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn git_clone_work_root_is_created_private_and_existing_loose_dir_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let created = temp.path().join("created");
        prepare_git_work_root(&created).await.unwrap();
        let created_mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(created_mode, 0o700);

        let loose = temp.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_git_work_root(&loose).await.unwrap_err();
        assert!(err.contains("group/world access bits"), "{err}");
    }

    #[tokio::test]
    async fn git_clone_route_rejects_malformed_json_without_minting() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));

        let response = handle_git_clone_request(&session, b"{not json", service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::InvalidRequest);
        assert!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_clone_route_maps_inactive_sessions_to_client_errors() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let request_body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let unknown_service =
            git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let unknown_response =
            handle_git_clone_request(&session, &request_body, unknown_service).await;

        assert_eq!(unknown_response.status, VmHttpStatus::Unauthorized);
        let unknown_body: VmGitCloneErrorResponse =
            serde_json::from_slice(&unknown_response.body).unwrap();
        assert_eq!(unknown_body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(unknown_body.message(), "session is not active");
        assert!(
            !unknown_body
                .message()
                .contains(&session.session_id().to_string())
        );

        open_audit_session(&state, session.session_id());
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();

        let closed_service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let closed_response =
            handle_git_clone_request(&session, &request_body, closed_service).await;

        assert_eq!(closed_response.status, VmHttpStatus::Gone);
        let closed_body: VmGitCloneErrorResponse =
            serde_json::from_slice(&closed_response.body).unwrap();
        assert_eq!(closed_body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(closed_body.message(), "session is closed");
        assert!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_clone_route_hides_host_mint_errors_from_vm_response() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string("backend detail /private/tmp/secret"),
            )
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let response = handle_git_clone_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::CloneFailed);
        assert_eq!(body.message(), "credential request failed");
        assert!(!body.message().contains("/private/tmp/secret"));
    }

    #[tokio::test]
    async fn git_clone_route_reports_cleanup_failure_without_returning_bundle() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_vm_token",
                "expires_at": expiry_str_from_now(3600),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let chmod = shell_single_quote(&required_test_tool("chmod"));
        let fake_git = write_fake_git_with_bundle_epilogue(
            temp.path(),
            &format!(
                r#"work_dir=${{bundle%/*}}
work_root=${{work_dir%/*}}
{chmod} 500 "$work_root""#
            ),
        );
        let service = git_clone_service_for_test(&state, &temp, fake_git);
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let response = handle_git_clone_request(&session, &body, service).await;

        let work_root = temp.path().join("git-work");
        std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::CloneFailed);
        assert!(
            body.message()
                .contains("temporary artifacts were not removed"),
            "{}",
            body.message()
        );
        assert!(!body.message().contains("bundle-from-fake-git"));
        assert_eq!(std::fs::read_dir(work_root).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn vm_http_git_clone_route_mints_host_token_and_returns_bundle() {
        use super::super::nix_cache::VmHttpNixCacheService;
        use super::super::tests::nix_cache_config_for_test;
        use tokio::sync::watch;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_vm_token",
                "expires_at": expiry_str_from_now(3600),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let fake_git = write_fake_git(temp.path());
        let service = git_clone_service_for_test(&state, &temp, fake_git);

        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(run_vm_http_with_services_until_shutdown(
            bound.into_listener(),
            session.clone(),
            service,
            VmHttpNixCacheService::new(Arc::clone(&state), nix_cache_config_for_test()),
            VmHttpProxies::none(),
            None,
            shutdown_rx,
        ));

        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_string(&VmGitCloneRequest::new(clone_repo, None)).unwrap();
        let response = request_over_tcp(
            addr,
            &format!(
                "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                bearer(token().as_str()),
                body.len(),
                body
            ),
        )
        .await;

        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains(&format!("content-type: {GIT_BUNDLE_CONTENT_TYPE}\r\n")),
            "{response}"
        );
        assert!(response.ends_with("bundle-from-fake-git\n"), "{response}");
        assert_eq!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .len(),
            1
        );

        let git_log = std::fs::read_to_string(temp.path().join("fake-git.log")).unwrap();
        assert!(git_log.contains("https://github.com/o/n.git"), "{git_log}");
        assert!(!git_log.contains("ghs_vm_token"), "{git_log}");
        let work_root_entries = std::fs::read_dir(temp.path().join("git-work"))
            .unwrap()
            .count();
        assert_eq!(work_root_entries, 0);
    }

    #[tokio::test]
    async fn vm_http_read_timeout_does_not_cancel_slow_git_clone_execution() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_delay(std::time::Duration::from_millis(100))
                    .set_body_json(serde_json::json!({
                        "token": "ghs_vm_token",
                        "expires_at": expiry_str_from_now(3600),
                        "permissions": {"contents": "read", "metadata": "read"},
                        "repository_selection": "selected",
                        "repositories": [{"full_name": "o/n"}]
                    })),
            )
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let fake_git = write_fake_git(temp.path());
        let service = git_clone_service_for_test(&state, &temp, fake_git);

        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_string(&VmGitCloneRequest::new(clone_repo, None)).unwrap();
        let request = format!(
            "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bearer(token().as_str()),
            body.len(),
            body
        );
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(handle_vm_http_connection_with_read_timeout(
            server_io,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
            session,
            services_with_git(service),
            std::time::Duration::from_millis(20),
        ));

        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap().unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("bundle-from-fake-git\n"), "{response}");
        let work_root_entries = std::fs::read_dir(temp.path().join("git-work"))
            .unwrap()
            .count();
        assert_eq!(work_root_entries, 0);
    }
}
