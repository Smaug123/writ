//! Tests for the VM HTTP surface: request parsing/limits, bearer/basic auth,
//! connection handling, routing, and response framing. Split out of `mod.rs`
//! (an inline `#[cfg(test)]` module) to keep the dispatch core readable; the
//! tests are unchanged. The `#[cfg(test)]` dispatch helpers they call
//! (`dispatch_vm_http_head`, `DispatchedTestResponse`) stay in `mod.rs` and are
//! reached via `super`.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use base64::Engine as _;
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::MockServer;

use super::*;
use crate::agent_run::AgentRunId;
use crate::audit::AuditLog;
use crate::core::{AgentKind, Ipv6Cidr, SessionRecord, TtlSeconds, UnixMillis};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::policy::PolicyConfig;
use crate::secret::{SecretError, SecretKey};
use crate::vm_git::GUEST_IMAGE_REBUILD_COMMAND;
use crate::vm_git::VM_GIT_CLONE_PATH;
use crate::vm_git::{BROKER_IMAGE_REBUILD_COMMAND, VM_FLAKE_PROVISION_PATH, VM_GIT_PUSH_PATH};
use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};
use std::collections::BTreeMap;

/// The per-step timeout every clone test hands the service. No test asserts on
/// it: the fake `git` is a shell script that returns at once, and the tests
/// assert on the response, the audit rows, or the work-root contents.
///
/// It is therefore set high enough that only a genuine wedge can reach it. A
/// bound that looks lavish beside a two-line script is not lavish at all when
/// the harness is oversubscribed and a thousand processes are contending for
/// eighteen cores; a 30s bound was reached there, and "clone mirror command
/// timed out after 30s" is a spectacularly misleading way to report that the
/// machine was busy (issue #355).
const TEST_GIT_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

type TestVmHttpServices = VmHttpServices<Box<dyn SecretStore>>;

pub(super) fn no_services() -> TestVmHttpServices {
    VmHttpServices::none()
}

pub(super) fn services_with_claude_proxy(
    claude_proxy: VmHttpClaudeProxyService<Box<dyn SecretStore>>,
) -> TestVmHttpServices {
    VmHttpServices {
        git_clone: None,
        nix_cache: None,
        claude_proxy: Some(claude_proxy),
        openai_proxy: None,
        agent_runs: None,
        git_push: None,
        flake_provision: None,
    }
}

#[derive(Default)]
struct InMemStore(Mutex<HashMap<String, String>>);

impl SecretStore for InMemStore {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
    }

    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.as_str().to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.0.lock().unwrap().remove(key.as_str());
        Ok(())
    }
}

const TEST_PRIV: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");

pub(super) fn session_for_subnet(ipv4: Ipv4Cidr) -> VmHttpSession {
    VmHttpSession::new(
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        ipv4,
        token(),
    )
}

pub(super) fn token() -> VmHttpBearerToken {
    VmHttpBearerToken::new("test-token-0123456789abcdef").unwrap()
}

pub(super) fn make_broker_state(server: &MockServer) -> Arc<BrokerState<Box<dyn SecretStore>>> {
    make_broker_state_with_extra_secret(server, None)
}

pub(super) fn make_broker_state_with_extra_secret(
    server: &MockServer,
    extra_secret: Option<(SecretKey, &str)>,
) -> Arc<BrokerState<Box<dyn SecretStore>>> {
    make_broker_state_with_extra_secrets(server, extra_secret.into_iter().collect())
}

pub(super) fn make_broker_state_with_extra_secrets(
    server: &MockServer,
    extra_secrets: Vec<(SecretKey, &str)>,
) -> Arc<BrokerState<Box<dyn SecretStore>>> {
    let pk = SecretKey::new("gh-app-pk").unwrap();
    let store = InMemStore::default();
    store.put(&pk, TEST_PRIV).unwrap();
    for (key, value) in extra_secrets {
        store.put(&key, value).unwrap();
    }
    let mut apps = BTreeMap::new();
    apps.insert(
        AgentKind::Claude,
        GitHubAppConfig {
            app_id: 42,
            installation_id: 999,
            installation_owner: "o".into(),
            private_key_secret: pk,
            api_base: server.uri(),
        },
    );
    Arc::new(BrokerState {
        audit: Arc::new(AuditLog::open_in_memory().unwrap()),
        minter: GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap()),
        secrets: Box::new(store) as Box<dyn SecretStore>,
        policy: PolicyConfig {
            writable_repos: vec![],
            default_ttl: TtlSeconds::new(3600).unwrap(),
        },
        staging_store: None,
        notes_repo: None,
        signing_key: None,
        run_agent_spawn: None,
        promote_runtime: None,
        git_data_http: std::sync::OnceLock::new(),
        mirror_pins: crate::vm_git_mirror_cache::MirrorPins::new(),
        chatgpt_oauth_authority: Default::default(),
    })
}

pub(super) fn open_audit_session(state: &BrokerState<Box<dyn SecretStore>>, session_id: SessionId) {
    state
        .audit
        .open_session(&SessionRecord {
            session_id,
            label: Some("vm-http-test".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::now(),
            closed_at: None,
        })
        .unwrap();
}

/// Record a contents-read grant for `repo` against `session_id`, as a clone
/// would, so a test can exercise endpoints that gate on a prior grant. The
/// session must already be open.
pub(super) fn record_contents_read_grant(
    state: &BrokerState<Box<dyn SecretStore>>,
    session_id: SessionId,
    repo: crate::core::RepoRef,
) {
    use crate::audit::PreMintRecord;
    use crate::core::{
        CapabilityRequest, CredentialGrant, GitHubAccess, GitHubGrantedScope, GitHubPermissions,
        GitHubRequest, GrantedScope, Jti, MetadataAccess, PolicyDecision, RequestId,
    };

    let request = CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Read,
        repo: repo.clone(),
    });
    let scope = GrantedScope::GitHub(GitHubGrantedScope {
        repository: repo,
        permissions: GitHubPermissions {
            contents: Some(GitHubAccess::Read),
            metadata: Some(MetadataAccess::Read),
            ..Default::default()
        },
    });
    let ttl = TtlSeconds::new(3600).unwrap();
    let decision = PolicyDecision::Grant {
        scope: scope.clone(),
        ttl,
    };
    let request_id = RequestId::new();
    let issued_at = UnixMillis::from_millis(1_700_000_000);
    state
        .audit
        .record_pre_mint(&PreMintRecord {
            request_id,
            session_id,
            received_at: issued_at,
            request: &request,
            decision: &decision,
        })
        .unwrap();
    state
        .audit
        .record_grant(&CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id,
            github_app_id: Some(42),
            scope,
            issued_at,
            expires_at: UnixMillis::from_millis(1_700_003_600),
        })
        .unwrap();
}

/// The commit hash the fake git's `rev-parse` reports, so a test that
/// configures a mirror cache can compute the `(repo, rev)` key the clone
/// handler retains under.
pub(super) const FAKE_GIT_REV_PARSE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

pub(super) fn write_fake_git(dir: &Path) -> PathBuf {
    write_fake_git_with_bundle_epilogue(dir, "")
}

pub(super) fn write_fake_git_with_bundle_epilogue(dir: &Path, bundle_epilogue: &str) -> PathBuf {
    let git = dir.join("fake-git.sh");
    let log_path = shell_single_quote(&dir.join("fake-git.log"));
    let shell = required_test_tool("sh");
    let mkdir = shell_single_quote(&required_test_tool("mkdir"));
    let script = format!(
        r#"#!{shell}
set -eu
printf '%s\n' "$*" >> {log}
case " $* " in
  *" clone "*)
if [ "${{WRIT_GIT_TOKEN:-}}" != "ghs_vm_token" ]; then
  exit 41
fi
mirror=
for arg do mirror=$arg; done
{mkdir} -p "$mirror"
;;
  *" bundle create "*)
if [ "${{WRIT_GIT_TOKEN+x}}" = x ]; then
  exit 42
fi
bundle=
after_separator=0
for arg do
  if [ "$after_separator" = 1 ]; then
    bundle=$arg
    break
  fi
  if [ "$arg" = "--" ]; then
    after_separator=1
  fi
done
if [ -z "$bundle" ]; then
  exit 43
fi
printf 'bundle-from-fake-git\n' > "$bundle"
{bundle_epilogue}
;;
  *" rev-parse "*)
printf '%s\n' '{sha}'
;;
  *)
exit 64
;;
esac
"#,
        shell = shell.display(),
        log = log_path,
        mkdir = mkdir,
        sha = FAKE_GIT_REV_PARSE_SHA,
        bundle_epilogue = bundle_epilogue,
    );
    std::fs::write(&git, script).unwrap();
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o700)).unwrap();
    git
}

pub(super) fn shell_single_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    format!("'{}'", raw.replace('\'', "'\\''"))
}

pub(super) fn required_test_tool(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("PATH must contain {name} for vm_http tests"));
    for dir in std::env::split_paths(&path) {
        let candidate = if dir.is_absolute() {
            dir.join(name)
        } else {
            std::env::current_dir().unwrap().join(dir).join(name)
        };
        match std::fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 => {
                return candidate;
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("failed to inspect {}: {err}", candidate.display()),
        }
    }
    panic!("required test tool {name} not found on PATH");
}

fn write_fake_askpass(dir: &Path) -> PathBuf {
    let askpass = dir.join("fake-askpass.sh");
    let shell = required_test_tool("sh");
    std::fs::write(&askpass, format!("#!{}\nexit 1\n", shell.display())).unwrap();
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    askpass
}

pub(super) fn git_clone_config_for_test(
    temp: &tempfile::TempDir,
    fake_git: PathBuf,
) -> VmHttpGitCloneConfig {
    let askpass = write_fake_askpass(temp.path());
    let credential =
        GitCredentialBoundary::new(askpass, GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap())
            .unwrap();
    VmHttpGitCloneConfig::new(
        fake_git,
        credential,
        temp.path().join("git-work"),
        TEST_GIT_CLONE_TIMEOUT,
        ByteSize::kib(1),
    )
    .unwrap()
}

pub(super) fn nix_cache_config_for_test() -> VmHttpNixCacheConfig {
    VmHttpNixCacheConfig::new("http://127.0.0.1:9", ByteSize::kib(1), ByteSize::kib(1)).unwrap()
}

/// Bind a free TCP port and release it, returning the port number — so a
/// test of the *fixed*-port binder has a port that is (momentarily) free.
async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test]
async fn bind_vm_http_listener_binds_the_requested_port() {
    let port = free_port().await;
    let bound = bind_vm_http_listener(Ipv4Addr::LOCALHOST, BrokerPort::new(port).unwrap())
        .await
        .unwrap();
    assert_eq!(bound.broker_port().get(), port);
    assert_eq!(bound.local_addr().unwrap().port(), port);
}

#[tokio::test]
async fn prepare_on_listener_uses_the_provided_bearer_and_bound_port() {
    let github = MockServer::start().await;
    let state = make_broker_state(&github);
    let temp = tempfile::tempdir().unwrap();
    let config = VmHttpRuntimeConfig::new(
        Ipv4Addr::LOCALHOST,
        BrokerPortRange::new(1024, 65535).unwrap(),
        git_clone_config_for_test(&temp, write_fake_git(temp.path())),
        nix_cache_config_for_test(),
        temp.path().join("git-push-staging"),
        VmGitPushBodyLimits::new(
            ByteSize::from_bytes(65 * 1024 * 1024),
            ByteSize::kib(16),
            ByteSize::mib(64),
        )
        .unwrap(),
    );
    let port = free_port().await;
    let listener = bind_vm_http_listener(Ipv4Addr::LOCALHOST, BrokerPort::new(port).unwrap())
        .await
        .unwrap();
    let bearer = VmHttpBearerToken::generate();
    let bearer_str = bearer.as_str().to_string();

    let prepared = prepare_vm_http_session_on_listener(
        Arc::clone(&state),
        &config,
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        bearer,
        listener,
        None,
        None,
    )
    .unwrap();

    // Unlike the ephemeral/generated host-broker path, both the port and the
    // bearer come from the caller (the broker-VM placement needs them fixed).
    assert_eq!(prepared.broker_port().get(), port);
    assert_eq!(prepared.bearer_token().as_str(), bearer_str);
}

fn request(source: Ipv4Addr, authorization: Option<String>) -> VmHttpRequest {
    VmHttpRequest::new(
        "GET",
        "/v1/session",
        authorization,
        SocketAddr::V4(SocketAddrV4::new(source, 34567)),
    )
}

/// The contract declaration `writ-vm` puts on every request it originates.
/// Full-dispatch tests send it because the guest they stand in for does; a test
/// that omits it is now asserting the *refusal* path, which is what
/// `the_contract_header_decides_exactly_the_routes_that_require_it` is for.
pub(super) fn declared_contract() -> String {
    VM_HTTP_CONTRACT_VERSION.to_string()
}

pub(super) fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}

pub(super) fn basic(value: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{VM_NIX_BASIC_LOGIN}:{value}").as_bytes())
    )
}

pub(super) async fn serve_raw_http_once(response: String) -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_for_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let read = stream.read(&mut buf).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = String::from_utf8_lossy(&request[..head_end]);
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while request.len() < head_end + content_length {
                    let read = stream.read(&mut buf).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                }
                break;
            }
        }
        *captured_for_task.lock().unwrap() = String::from_utf8_lossy(&request).into_owned();
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (format!("http://{addr}/"), captured)
}

pub(super) fn raw_http_response(status: &str, content_type: &str, body: &[u8]) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
}

pub(super) fn raw_http_response_with_headers(
    status: &str,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len(),
    );
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&String::from_utf8_lossy(body));
    response
}

fn arbitrary_socket_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(octets, port)| SocketAddr::new(Ipv4Addr::from(octets).into(), port)),
        (any::<[u16; 8]>(), any::<u16>()).prop_map(|(segments, port)| {
            SocketAddr::new(
                Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7],
                )
                .into(),
                port,
            )
        }),
    ]
}

fn arbitrary_header() -> impl Strategy<Value = Option<String>> {
    prop::option::of(
        prop::collection::vec(any::<char>(), 0..128).prop_map(|chars| chars.into_iter().collect()),
    )
}

#[test]
fn bearer_token_debug_redacts_secret() {
    let token = token();
    assert_eq!(format!("{token:?}"), "VmHttpBearerToken(<redacted>)");
}

#[test]
fn bearer_token_rejects_empty_or_header_unsafe_values() {
    assert_eq!(
        VmHttpBearerToken::new(""),
        Err(VmHttpConfigError::EmptyBearerToken)
    );
    assert_eq!(
        VmHttpBearerToken::new("has space"),
        Err(VmHttpConfigError::InvalidBearerToken)
    );
    assert_eq!(
        VmHttpBearerToken::new("has\nnewline"),
        Err(VmHttpConfigError::InvalidBearerToken)
    );
    for token in ["has+plus", "has/slash", "has=equals", "has:colon", "has@at"] {
        assert_eq!(
            VmHttpBearerToken::new(token),
            Err(VmHttpConfigError::InvalidBearerToken),
            "accepted {token:?}"
        );
    }
}

#[test]
fn generated_bearer_tokens_are_distinct_and_header_safe() {
    let first = VmHttpBearerToken::generate();
    let second = VmHttpBearerToken::generate();
    assert_ne!(first, second);
    assert!(first.as_str().bytes().all(is_bearer_token_byte));
}

proptest! {
    #[test]
    fn authorization_accepts_any_source_inside_session_subnet(
        second in any::<u8>(),
        third in any::<u8>(),
        host in 1u8..=254,
    ) {
        let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
        let session = session_for_subnet(subnet);
        let source = Ipv4Addr::new(10, second, third, host);
        let got = authorize_vm_http_request(&session, &request(source, Some(bearer(token().as_str()))));
        prop_assert_eq!(got, VmHttpAuthorization::Allow);
    }

    #[test]
    fn authorization_rejects_any_source_outside_session_subnet(
        second in any::<u8>(),
        third in any::<u8>(),
        other_third in any::<u8>(),
        host in 1u8..=254,
    ) {
        let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
        let session = session_for_subnet(subnet);
        let outside_third = if other_third == third { other_third.wrapping_add(1) } else { other_third };
        let source = Ipv4Addr::new(10, second, outside_third, host);
        let got = authorize_vm_http_request(&session, &request(source, Some(bearer(token().as_str()))));
        prop_assert_eq!(
            got,
            VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet)
        );
    }

    #[test]
    fn authorization_is_total_for_any_peer_and_header(
        second in any::<u8>(),
        third in any::<u8>(),
        peer_addr in arbitrary_socket_addr(),
        authorization in arbitrary_header(),
    ) {
        let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
        let session = session_for_subnet(subnet);
        let request = VmHttpRequest::new("GET", "/v1/session", authorization, peer_addr);
        let _ = authorize_vm_http_request(&session, &request);
    }
}

#[test]
fn authorization_rejects_missing_or_wrong_bearer_token() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let source = Ipv4Addr::new(10, 1, 2, 42);

    assert_eq!(
        authorize_vm_http_request(&session, &request(source, None)),
        VmHttpAuthorization::Deny(VmHttpAuthError::MissingCredentials)
    );
    assert_eq!(
        authorize_vm_http_request(&session, &request(source, Some("Basic nope".into()))),
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    );
    assert_eq!(
        authorize_vm_http_request(&session, &request(source, Some(bearer("wrong")))),
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    );
}

#[test]
fn non_nix_routes_do_not_accept_basic_auth() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let source = Ipv4Addr::new(10, 1, 2, 42);

    assert_eq!(
        authorize_vm_http_request(&session, &request(source, Some(basic(token().as_str())))),
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    );
}

#[test]
fn authorization_rejects_ipv6_sources() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let request = VmHttpRequest::new(
        "GET",
        "/v1/session",
        Some(bearer(token().as_str())),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 34567, 0, 0)),
    );
    assert_eq!(
        authorize_vm_http_request(&session, &request),
        VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet)
    );
}

#[test]
fn parser_rejects_duplicate_authorization_header() {
    let request = http::Request::builder()
        .method("GET")
        .uri("/v1/session")
        .header("authorization", "Bearer a")
        .header("authorization", "Bearer b")
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();
    let err = VmHttpRequest::from_hyper_parts(
        &parts,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
    )
    .unwrap_err();
    assert_eq!(err, VmHttpParseError::DuplicateAuthorization);
}

#[test]
fn parser_rejects_duplicate_content_length_header() {
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/git/clone")
        .header("content-length", "2")
        .header("content-length", "2")
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();
    let err = VmHttpRequest::from_hyper_parts(
        &parts,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
    )
    .unwrap_err();
    assert_eq!(err, VmHttpParseError::DuplicateContentLength);
}

#[test]
fn parser_rejects_duplicate_authorization_when_one_value_is_non_utf8() {
    let invalid = http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
    let request = http::Request::builder()
        .method("GET")
        .uri("/v1/session")
        .header("authorization", "Bearer a")
        .header("authorization", invalid)
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();
    let err = VmHttpRequest::from_hyper_parts(
        &parts,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
    )
    .unwrap_err();
    assert_eq!(err, VmHttpParseError::DuplicateAuthorization);
}

#[test]
fn parser_rejects_duplicate_content_length_when_one_value_is_non_utf8() {
    let invalid = http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/git/clone")
        .header("content-length", "5")
        .header("content-length", invalid)
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();
    let err = VmHttpRequest::from_hyper_parts(
        &parts,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
    )
    .unwrap_err();
    assert_eq!(err, VmHttpParseError::DuplicateContentLength);
}

#[test]
fn authenticated_session_route_returns_session_identity() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let bearer_auth = bearer(token().as_str());
    let response = dispatch_vm_http_head(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        "GET",
        "/v1/session",
        Some(bearer_auth.as_str()),
    );
    assert_eq!(response.status, VmHttpStatus::Ok);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["session_id"], session.session_id().to_string());
    assert_eq!(body["api"], "writ-vm-http");
    // The compiled contract version, not a literal: this endpoint is how a guest
    // learns whether its image matches the broker, so what matters is that it
    // reports the constant the guest compares against. Deliberate bumps are
    // forced by `broker_contract_fingerprint_is_pinned`, not here.
    assert_eq!(body["version"], crate::vm_git::VM_HTTP_CONTRACT_VERSION);
}

#[test]
fn every_route_requires_auth_before_path_or_method_checks() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let response = dispatch_vm_http_head(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        "POST",
        "/not-real",
        None,
    );
    assert_eq!(response.status, VmHttpStatus::Unauthorized);
}

#[test]
fn authenticated_unknown_route_is_not_found() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let bearer_auth = bearer(token().as_str());
    let response = dispatch_vm_http_head(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        "GET",
        "/unknown",
        Some(bearer_auth.as_str()),
    );
    assert_eq!(response.status, VmHttpStatus::NotFound);
}

#[tokio::test]
async fn disabled_agent_run_config_route_is_not_found() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let run_id: AgentRunId = "00000000-0000-0000-0000-000000000402".parse().unwrap();
    let target = crate::agent_run::vm_agent_run_config_path(run_id);
    let request = VmHttpRequest::new(
        "GET",
        &target,
        Some(bearer(token().as_str())),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
    );

    let response = resolve_and_route_authenticated_vm_http_request(
        &session,
        &request,
        Vec::new(),
        no_services(),
    )
    .await
    .into_buffered();

    assert_eq!(response.status, VmHttpStatus::NotFound);
}

/// **The contract header is what makes the difference, and only where it should.**
///
/// Driven over the whole endpoint map, so totality comes from
/// `the_endpoint_map_covers_every_route`: a new route joins this test the moment
/// it is documented, and must then behave as its own `contract_check` says.
///
/// For an exempt route the header must be *inert* — a third-party client will
/// never send one, so any difference is a client we would break. For a required
/// route it must be decisive.
#[tokio::test]
async fn the_contract_header_decides_exactly_the_routes_that_require_it() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
    let declared = VM_HTTP_CONTRACT_VERSION.to_string();

    for (method, target, name) in crate::vm_http::route_table::tests::ENDPOINT_MAP {
        let (method, target) = (*method, *target);
        let with = dispatch_declaring(&session, method, target, Some(&declared)).await;
        let without = dispatch_declaring(&session, method, target, None).await;

        let route = VmHttpRoute::resolve(&VmHttpRequest::new(
            method,
            target,
            None,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        ));
        match route.contract_check() {
            ContractCheck::Exempt(_) => {
                assert_eq!(
                    with.status, without.status,
                    "`{name}` is exempt, so the contract header must make no difference to it \
                     ({method} {target})",
                );
                assert_ne!(without.status, VmHttpStatus::UpgradeRequired, "{name}");
            }
            ContractCheck::Required => {
                assert_eq!(
                    without.status,
                    VmHttpStatus::UpgradeRequired,
                    "`{name}` requires a contract declaration and must refuse a request without \
                     one ({method} {target})",
                );
                assert_ne!(
                    with.status,
                    VmHttpStatus::UpgradeRequired,
                    "`{name}` refused a request that declared the matching version ({method} \
                     {target})",
                );
            }
        }
    }
}

/// A guest declaring the *wrong* version is refused just as one declaring
/// nothing is, and told which side is stale. A newer guest is told to restart
/// the daemon, not to rebuild itself into the same image again.
#[tokio::test]
async fn a_mismatched_declaration_names_the_stale_side() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());

    for (declared, expected_remedy) in [
        (
            (VM_HTTP_CONTRACT_VERSION + 1).to_string(),
            BROKER_IMAGE_REBUILD_COMMAND,
        ),
        (
            VM_HTTP_CONTRACT_VERSION.saturating_sub(1).to_string(),
            GUEST_IMAGE_REBUILD_COMMAND,
        ),
        ("not-a-version".to_string(), GUEST_IMAGE_REBUILD_COMMAND),
    ] {
        let response =
            dispatch_declaring(&session, "POST", VM_GIT_PUSH_PATH, Some(&declared)).await;

        assert_eq!(response.status, VmHttpStatus::UpgradeRequired, "{declared}");
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            body.contains(expected_remedy),
            "declaring `{declared}` against broker {VM_HTTP_CONTRACT_VERSION} must name \
             `{expected_remedy}`: {body}",
        );
    }
}

/// **The refusal comes before the body is read.** A stale guest's oversized push
/// must be refused for the reason that is true of it, not buffered to the limit
/// first and then rejected for its size — buffering work for a request already
/// decided against is exactly the unbounded work this ordering exists to avoid.
#[tokio::test]
async fn the_contract_check_runs_before_the_body_is_read() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
    let oversized = (MAX_VM_HTTP_BODY_BYTES.get() + 1).to_string();

    let response = dispatch_vm_http_head_and_body(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        "POST",
        VM_FLAKE_PROVISION_PATH,
        &[
            ("authorization", bearer(token().as_str()).as_str()),
            ("content-length", oversized.as_str()),
        ],
        Vec::new(),
        no_services(),
        VM_HTTP_READ_TIMEOUT,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::UpgradeRequired);
}

/// ...and after authentication, so an unauthenticated peer cannot learn which
/// contract version this broker speaks by asking.
#[tokio::test]
async fn authorization_runs_before_the_contract_check() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());

    let response = dispatch_vm_http_head_and_body(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        "POST",
        VM_GIT_PUSH_PATH,
        &[("authorization", "Bearer not-the-session-token")],
        Vec::new(),
        no_services(),
        VM_HTTP_READ_TIMEOUT,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::Unauthorized);
}

/// **Two declarations are no declaration.** A request carrying the right version
/// *and* a second occurrence is refused, whether or not that second occurrence
/// is even text — a header value is opaque octets, so filtering the undecodable
/// ones out before counting would let a valid header plus junk pass as a single
/// valid declaration.
#[tokio::test]
async fn a_duplicated_contract_declaration_is_refused() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());

    for second in [b"3".as_slice(), b"9".as_slice(), &[0xff, 0xfe][..]] {
        let request = http::Request::builder()
            .method("POST")
            .uri(VM_GIT_PUSH_PATH)
            .header("authorization", bearer(token().as_str()))
            .header(VM_HTTP_CONTRACT_HEADER, declared_contract())
            .header(
                VM_HTTP_CONTRACT_HEADER,
                http::HeaderValue::from_bytes(second).unwrap(),
            )
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("test request builds with valid method/uri/headers");

        let response = serve_vm_http_request(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            request,
            no_services(),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(
            DispatchedTestResponse::from_hyper_response(response)
                .await
                .status,
            VmHttpStatus::UpgradeRequired,
            "a second declaration of {second:?} must not be discarded",
        );
    }
}

/// One authenticated request, optionally declaring a contract version, through
/// the production dispatch — services unconfigured, since these tests are about
/// which stage answers, not what the handler would have said.
async fn dispatch_declaring(
    session: &VmHttpSession,
    method: &str,
    target: &str,
    declared: Option<&str>,
) -> DispatchedTestResponse {
    let authorization = bearer(token().as_str());
    let mut headers = vec![("authorization", authorization.as_str())];
    if let Some(declared) = declared {
        headers.push((VM_HTTP_CONTRACT_HEADER, declared));
    }
    dispatch_vm_http_head_and_body(
        session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        method,
        target,
        &headers,
        Vec::new(),
        no_services(),
        VM_HTTP_READ_TIMEOUT,
    )
    .await
}

#[tokio::test]
async fn authorization_runs_before_body_limit_enforcement() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let oversized = (MAX_VM_HTTP_BODY_BYTES.get() + 1).to_string();
    let response = dispatch_vm_http_head_and_body(
        &session,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        "POST",
        VM_GIT_CLONE_PATH,
        &[("content-length", oversized.as_str())],
        Vec::new(),
        no_services(),
        VM_HTTP_READ_TIMEOUT,
    )
    .await;
    assert_eq!(response.status, VmHttpStatus::Unauthorized);
}

#[tokio::test]
async fn session_route_does_not_read_declared_body() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let bearer_auth = bearer(token().as_str());
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            "/v1/session",
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
    .expect("session route must not wait for a declared body");

    assert_eq!(response.status, VmHttpStatus::Ok);
}

#[tokio::test]
async fn prepare_vm_http_session_returns_in_range_broker_port_and_redacted_token() {
    let github = MockServer::start().await;
    let state = make_broker_state(&github);
    let temp = tempfile::tempdir().unwrap();
    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let config = VmHttpRuntimeConfig::new(
        Ipv4Addr::LOCALHOST,
        range,
        git_clone_config_for_test(&temp, write_fake_git(temp.path())),
        nix_cache_config_for_test(),
        temp.path().join("git-push-staging"),
        VmGitPushBodyLimits::new(
            ByteSize::from_bytes(65 * 1024 * 1024),
            ByteSize::kib(16),
            ByteSize::mib(64),
        )
        .unwrap(),
    );
    let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
    let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();

    let prepared = prepare_vm_http_session(state, &config, session_id, source_ipv4)
        .await
        .unwrap();

    assert!(range.contains(prepared.broker_port()));
    assert_eq!(prepared.session().session_id(), session_id);
    assert_eq!(prepared.session().source_ipv4(), source_ipv4);
    assert!(prepared.bearer_token().as_str().starts_with("writ-vm-"));
    assert!(!format!("{:?}", prepared.bearer_token()).contains(prepared.bearer_token().as_str()));
}

#[tokio::test]
async fn running_runtime_serves_session_and_shuts_down() {
    let github = MockServer::start().await;
    let state = make_broker_state(&github);
    let temp = tempfile::tempdir().unwrap();
    let config = VmHttpRuntimeConfig::new(
        Ipv4Addr::LOCALHOST,
        BrokerPortRange::new(1024, 65535).unwrap(),
        git_clone_config_for_test(&temp, write_fake_git(temp.path())),
        nix_cache_config_for_test(),
        temp.path().join("git-push-staging"),
        VmGitPushBodyLimits::new(
            ByteSize::from_bytes(65 * 1024 * 1024),
            ByteSize::kib(16),
            ByteSize::mib(64),
        )
        .unwrap(),
    );
    let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
    let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();
    let prepared = prepare_vm_http_session(state, &config, session_id, source_ipv4)
        .await
        .unwrap();
    let addr = prepared.local_addr().unwrap();
    let token = prepared.bearer_token().as_str().to_string();

    let running = prepared.spawn();
    let response = request_over_tcp(
        addr,
        &format!(
            "GET /v1/session HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\n\r\n",
            bearer(&token)
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains(&session_id.to_string()), "{response}");
    assert_eq!(running.bearer_token().as_str(), token);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn bind_ephemeral_listener_reserves_an_allowed_broker_port() {
    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap();
    assert!(range.contains(bound.broker_port()));
    let addr = bound.local_addr().unwrap();
    let second_bind = TcpListener::bind(addr).await.unwrap_err();
    assert_eq!(second_bind.kind(), std::io::ErrorKind::AddrInUse);
    drop(bound);
}

#[tokio::test]
async fn bind_ephemeral_listener_scans_exact_small_allowed_range() {
    for _ in 0..64 {
        let probe = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let range = BrokerPortRange::new(port, port).unwrap();
        match bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range).await {
            Ok(bound) => {
                assert_eq!(bound.broker_port().get(), port);
                return;
            }
            Err(VmHttpBindError::NoAllowedPort { .. }) => {}
            Err(err) => panic!("unexpected bind error: {err}"),
        }
    }

    panic!("could not find a reusable one-port range for VM HTTP bind test");
}

#[tokio::test]
async fn bind_ephemeral_listener_fails_when_small_allowed_range_is_occupied() {
    let occupied = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let range = BrokerPortRange::new(port, port).unwrap();

    let err = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap_err();

    match err {
        VmHttpBindError::NoAllowedPort { min, max, .. } => {
            assert_eq!(min, port);
            assert_eq!(max, port);
        }
        VmHttpBindError::Io(err) => panic!("unexpected IO error: {err}"),
    }
}

#[tokio::test]
async fn vm_http_server_serves_authenticated_session_request() {
    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap();
    let addr = bound.local_addr().unwrap();
    let session = VmHttpSession::new(
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        token(),
    );
    let server = tokio::spawn(run_vm_http(bound.into_listener(), session.clone()));

    let response = request_over_tcp(
        addr,
        &format!(
            "GET /v1/session HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\n\r\n",
            bearer(token().as_str())
        ),
    )
    .await;

    server.abort();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.contains(&session.session_id().to_string()),
        "{response}"
    );
}

#[tokio::test]
async fn vm_http_server_rejects_missing_auth() {
    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap();
    let addr = bound.local_addr().unwrap();
    let session = VmHttpSession::new(
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        token(),
    );
    let server = tokio::spawn(run_vm_http(bound.into_listener(), session));

    let response =
        request_over_tcp(addr, "GET /v1/session HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

    server.abort();
    assert!(
        response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{response}"
    );
    assert!(response.contains("www-authenticate: Bearer"), "{response}");
}

#[tokio::test]
async fn vm_http_server_exits_when_shutdown_signal_set() {
    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap();
    let session = VmHttpSession::new(
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        token(),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(run_vm_http_until_shutdown(
        bound.into_listener(),
        session,
        shutdown_rx,
    ));

    shutdown_tx.send(true).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires host Nix; proves real Nix netrc auth against the VM HTTP cache route"]
async fn nix_cli_can_authenticate_to_vm_http_nix_cache_route_with_netrc() {
    let _nix = required_test_tool("nix");
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    let token = token();
    std::fs::write(
        &netrc,
        format!(
            "machine 127.0.0.1 login {VM_NIX_BASIC_LOGIN} password {}\n",
            token.as_str()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&netrc, std::fs::Permissions::from_mode(0o600)).unwrap();

    let range = BrokerPortRange::new(1024, 65535).unwrap();
    let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
        .await
        .unwrap();
    let addr = bound.local_addr().unwrap();
    let session = VmHttpSession::new(
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
        Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        token.clone(),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(run_vm_http_until_shutdown(
        bound.into_listener(),
        session,
        shutdown_rx,
    ));

    let store_url = format!(
        "http://127.0.0.1:{port}{VM_NIX_CACHE_PATH_PREFIX}",
        port = addr.port()
    );
    let store_path = "/nix/store/00000000000000000000000000000000-writ-nix-route-proof";
    let args = [
        "path-info",
        "--refresh",
        "--store",
        &store_url,
        "--option",
        "experimental-features",
        "nix-command",
        "--option",
        "access-tokens",
        "",
        "--option",
        "substituters",
        "",
        "--option",
        "trusted-public-keys",
        "",
        "--option",
        "netrc-file",
        netrc.to_str().unwrap(),
        store_path,
    ];
    for arg in &args {
        assert!(!arg.contains(token.as_str()), "token leaked into Nix argv");
    }
    assert!(!store_url.contains(token.as_str()));

    let home = temp.path().join("home");
    let xdg_config = temp.path().join("xdg-config");
    let nix_conf = temp.path().join("nix-conf");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&xdg_config).unwrap();
    std::fs::create_dir(&nix_conf).unwrap();
    std::fs::write(nix_conf.join("nix.conf"), "").unwrap();

    let output = tokio::process::Command::new("nix")
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("NIX_CONF_DIR", &nix_conf)
        .env("NIX_CONFIG", "")
        .env("TMPDIR", std::env::temp_dir())
        .output()
        .await
        .unwrap();

    shutdown_tx.send(true).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "proof path should miss in the skeleton cache\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!stdout.contains(token.as_str()), "token leaked to stdout");
    assert!(!stderr.contains(token.as_str()), "token leaked to stderr");
    assert!(!stderr.contains("401"), "Nix was not authorized:\n{stderr}");
    assert!(!stderr.contains("403"), "Nix was forbidden:\n{stderr}");
    assert!(
        stderr.contains("404") || stderr.contains("is not valid"),
        "expected authenticated cache miss, got status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
}

async fn request_over_tcp(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[test]
fn source_subnet_can_be_taken_from_agent_network_ipv4() {
    let pool = crate::core::AgentNetworkPool::new(
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
        Ipv6Cidr::new("fd83:b6f2:e57::".parse::<std::net::Ipv6Addr>().unwrap(), 48).unwrap(),
    )
    .unwrap();
    let network = pool.allocate(252).unwrap();
    let session = VmHttpSession::new(
        session_for_subnet(network.ipv4()).session_id(),
        network.ipv4(),
        token(),
    );
    assert_eq!(session.source_ipv4(), network.ipv4());
}

/// The pre-split model-proxy paths are simply unknown endpoints now. The `410`
/// shim that named the rebuild is deleted: the only client that could ask for
/// these is a guest image built before the split, and such an image declares no
/// contract version, so it is refused at `workspace init` with a `426` naming
/// the same remedy — before any agent process exists to issue a model request.
/// Nothing may be recorded, because no effect was attempted.
#[tokio::test]
async fn a_pre_split_proxy_path_is_unknown_and_records_nothing() {
    let github = MockServer::start().await;
    let state = make_broker_state(&github);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
    open_audit_session(&state, session.session_id());
    let request = VmHttpRequest::new(
        "POST",
        "/v1/messages",
        Some(bearer(token().as_str())),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
    );

    let response = resolve_and_route_authenticated_vm_http_request(
        &session,
        &request,
        Vec::new(),
        no_services(),
    )
    .await
    .into_buffered();

    assert_eq!(response.status, VmHttpStatus::NotFound);
    // A retired path attempts no effect, so it records none.
    state.audit.assert_effect_audit_pairs_complete(
        "claude_proxy_request",
        "claude_proxy_outcome",
        "request_id",
    );
    assert_eq!(
        state.audit.table_row_count_for_test("claude_proxy_request"),
        0
    );
    assert_eq!(
        state.audit.table_row_count_for_test("openai_proxy_request"),
        0
    );
}

/// The Stage-6 capstone oracle: **every** registered brokered route, driven
/// end to end through the dispatcher, leaves a complete `(request, outcome)`
/// audit pair.
///
/// This is the executable form of "complete by construction". The loop is
/// driven by [`BrokeredRoute::ALL_NAMES`], which the route-table macro generates
/// from the enum definition itself — so a new capability cannot be added
/// without appearing here, and the `_` arm below fails loudly until it is
/// actually driven. Coverage therefore grows with the route table rather than
/// with anyone remembering to write a test.
///
/// Each route is checked twice over: a non-vacuity guard (the drive really
/// recorded a request row, so a silently-skipped drive cannot pass) and the
/// pair assertion itself.
mod brokered_route_audit_oracle {
    use super::super::claude_proxy::VM_CLAUDE_MESSAGES_PATH;
    use super::super::openai_proxy::VM_OPENAI_RESPONSES_PATH;
    use super::*;
    use crate::agent_run::{
        AgentRunStreamUpload, VmAgentRunOutcomeUpload, vm_agent_run_outcome_path,
    };
    use crate::audit::AgentRunAuditRecord;
    use crate::core::RepoRef;
    use crate::git_push_staging::GitPushStagingStore;
    use crate::vm_git::{
        GitBranchName, GitCloneRepo, GitObjectId, VM_FLAKE_PROVISION_PATH, VM_GIT_PUSH_PATH,
        VmFlakeProvisionRequest, VmGitPushBodyLimits, VmGitPushMetadata, VmGitPushRequest,
        encode_vm_git_push_request_body,
    };
    use crate::vm_git_mirror_cache::{MirrorCache, MirrorCacheKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    /// The `(request table, outcome table, join column)` a route records into.
    fn audit_pair_for(route: &str) -> (&'static str, &'static str, &'static str) {
        match route {
            "ClaudeProxy" => ("claude_proxy_request", "claude_proxy_outcome", "request_id"),
            "OpenAiProxy" => ("openai_proxy_request", "openai_proxy_outcome", "request_id"),
            "NixCache" => ("nix_cache_request", "nix_cache_outcome", "request_id"),
            "GitPush" => ("git_push_request", "git_push_outcome", "push_request_id"),
            "FlakeProvision" => (
                "flake_provision_request",
                "flake_provision_outcome",
                "request_id",
            ),
            "AgentRunOutcome" => ("agent_run", "agent_run_outcome", "run_id"),
            other => panic!(
                "brokered route `{other}` has no audit pair listed here: every brokered route \
                 records a (request, outcome) pair, so name its tables and drive it below",
            ),
        }
    }

    /// The broker the audit oracles drive: every service configured, a real
    /// bare mirror behind flake provisioning, a launched agent run for the
    /// outcome route to resume, and mock upstreams for the two proxies.
    ///
    /// Shared by the pair oracle and the contract-refusal oracle below, so both
    /// speak to the *same* broker — a refusal that recorded nothing against a
    /// differently-configured broker would prove much less.
    struct AuditOracleBroker {
        state: Arc<BrokerState<Box<dyn SecretStore>>>,
        session: VmHttpSession,
        services: TestVmHttpServices,
        repo: RepoRef,
        rev: crate::vm_git_mirror_cache::GitCommitSha,
        run_id: AgentRunId,
        // Kept alive for the lifetime of the fixture: the mock upstreams stop
        // serving when dropped, and the temp dir takes the staging, cache and
        // materialisation roots with it.
        _temp: tempfile::TempDir,
        _upstreams: Vec<MockServer>,
    }

    impl AuditOracleBroker {
        async fn build() -> Self {
            let git_program = required_test_tool("git");
            let temp = tempfile::tempdir().unwrap();

            // Upstreams for the two model proxies. Plain JSON, so both responses
            // buffer rather than stream.
            let claude_upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/messages"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(b"{}".to_vec(), "application/json"),
                )
                .mount(&claude_upstream)
                .await;
            let openai_upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/responses"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(b"{}".to_vec(), "application/json"),
                )
                .mount(&openai_upstream)
                .await;

            let github = MockServer::start().await;
            let anthropic_key = SecretKey::new("anthropic-api-key").unwrap();
            let openai_key = SecretKey::new("openai-api-key").unwrap();
            let state = make_broker_state_with_extra_secrets(
                &github,
                vec![
                    (anthropic_key.clone(), "host-anthropic-key"),
                    (openai_key.clone(), "host-openai-key"),
                ],
            );
            let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
            open_audit_session(&state, session.session_id());

            // A real bare mirror plus a fake `nix` that archives, so flake
            // provisioning runs its full audited path without needing a nix daemon.
            let repo = RepoRef {
                owner: "o".into(),
                name: "n".into(),
            };
            let (mirror, rev) = crate::flake_fixtures::no_input_flake_mirror(
                &git_program,
                &temp.path().join("flake-fixture"),
            );
            let mirror_cache = MirrorCache::new(temp.path().join("mirror-cache"));
            mirror_cache
                .insert(&MirrorCacheKey::new(&repo, &rev), &mirror)
                .unwrap();
            record_contents_read_grant(&state, session.session_id(), repo.clone());

            // The agent run whose outcome the outcome route resumes.
            let run_id = AgentRunId::new();
            state
                .audit
                .record_agent_run(&AgentRunAuditRecord {
                    run_id,
                    session_id: session.session_id(),
                    requested_at: UnixMillis::now(),
                    agent_kind: AgentKind::Claude,
                    prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
                    correlation_id: None,
                })
                .unwrap();

            let services = TestVmHttpServices {
                git_clone: None,
                nix_cache: Some(VmHttpNixCacheService::new(
                    Arc::clone(&state),
                    nix_cache_config_for_test(),
                )),
                claude_proxy: Some(
                    VmHttpClaudeProxyService::new(
                        Arc::clone(&state),
                        VmHttpClaudeProxyConfig::new_with_anthropic_version(
                            claude_upstream.uri(),
                            anthropic_key,
                            VmHttpClaudeProxyAuthKind::XApiKey,
                            "2024-10-22",
                            std::time::Duration::from_secs(5),
                            ByteSize::from_bytes(4096),
                            ByteSize::from_bytes(4096),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
                openai_proxy: Some(
                    VmHttpOpenAiProxyService::new(
                        Arc::clone(&state),
                        VmHttpOpenAiProxyConfig::new(
                            openai_upstream.uri(),
                            openai_key,
                            VmHttpOpenAiProxyAuthKind::AuthorizationBearer,
                            std::time::Duration::from_secs(5),
                            ByteSize::from_bytes(4096),
                            ByteSize::from_bytes(4096),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
                agent_runs: Some(VmHttpAgentRunService::new(
                    Arc::clone(&state),
                    temp.path().join("agent-runs"),
                )),
                git_push: Some(VmHttpGitPushService::new(
                    Arc::clone(&state),
                    Arc::new(GitPushStagingStore::open(temp.path().join("staging")).unwrap()),
                    VmGitPushBodyLimits::new(
                        ByteSize::kib(64),
                        ByteSize::kib(8),
                        ByteSize::kib(64),
                    )
                    .unwrap(),
                )),
                flake_provision: Some(VmHttpFlakeProvisionService::new(
                    Arc::clone(&state),
                    VmHttpFlakeProvisionConfig::new(
                        crate::flake_provision_from_mirror::MirrorFlakeProvisionConfig::new(
                            git_program,
                            crate::flake_fixtures::fake_nix_archiving(temp.path()),
                            temp.path().join("materialize"),
                            temp.path().join("flake-input-cache"),
                            crate::flake_lock::FlakeProvisionBounds::new(
                                64,
                                ByteSize::gib(1),
                                std::time::Duration::from_secs(120),
                            )
                            .unwrap(),
                            std::time::Duration::from_secs(120),
                        ),
                        mirror_cache,
                    ),
                )),
            };

            Self {
                state,
                session,
                services,
                repo,
                rev,
                run_id,
                _temp: temp,
                _upstreams: vec![claude_upstream, openai_upstream, github],
            }
        }
    }

    #[tokio::test]
    async fn every_brokered_route_records_a_complete_audit_pair() {
        // Bound whole, never destructured: the fixture's `_temp` / `_upstreams`
        // fields keep the staging dir and the mock upstreams alive, and a
        // by-value destructure with `..` would drop them right here.
        let broker = AuditOracleBroker::build().await;
        let (state, session, services, repo, rev, run_id) = (
            &broker.state,
            &broker.session,
            &broker.services,
            &broker.repo,
            &broker.rev,
            broker.run_id,
        );

        for route in BrokeredRoute::ALL_NAMES {
            let (request_table, outcome_table, join_column) = audit_pair_for(route);
            // Non-vacuity is measured on the *outcome* table, uniformly: it is
            // the half every drive must add. (A two-phase route adds both rows;
            // an outcome-only route's request row was written by an earlier
            // lifecycle event — the agent run's launch — so counting request
            // rows would report no progress for it.)
            let before = state.audit.table_row_count_for_test(outcome_table);

            let (request, body) = drive_for(route, repo, rev, run_id);
            let dispatch = super::super::resolve_and_route_authenticated_vm_http_request(
                session,
                &request,
                body,
                services.clone(),
            )
            .await;
            // Drop any streaming body so a `Drop`-time outcome write lands
            // before the assertions below.
            drop(dispatch);

            assert!(
                state.audit.table_row_count_for_test(outcome_table) > before,
                "driving `{route}` recorded no `{outcome_table}` row — the drive did not reach \
                 the effect, so the pair assertion below would pass vacuously",
            );
            assert!(
                state.audit.table_row_count_for_test(request_table) > 0,
                "`{route}` recorded an outcome with no `{request_table}` row behind it",
            );
            state.audit.assert_effect_audit_pairs_complete(
                request_table,
                outcome_table,
                join_column,
            );
        }
    }

    /// **A refused guest reaches no effect and records nothing.**
    ///
    /// Drives the *same* requests as the pair oracle above, against the *same*
    /// broker, through the production dispatch and without a contract
    /// declaration. Reusing `drive_for` is what makes this non-vacuous: the
    /// oracle above proves those exact drives reach the effect and record a
    /// pair, so a run here that records nothing did so because it was refused,
    /// not because the drive was inert.
    #[tokio::test]
    async fn a_guest_that_declares_no_contract_records_nothing_on_a_required_route() {
        let broker = AuditOracleBroker::build().await;

        for route in BrokeredRoute::ALL_NAMES {
            let (request, body) = drive_for(route, &broker.repo, &broker.rev, broker.run_id);
            if VmHttpRoute::resolve(&request).contract_check() != ContractCheck::Required {
                continue;
            }
            let (request_table, outcome_table, _) = audit_pair_for(route);
            let before = (
                broker.state.audit.table_row_count_for_test(request_table),
                broker.state.audit.table_row_count_for_test(outcome_table),
            );

            let response = dispatch_vm_http_head_and_body(
                &broker.session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
                &request.method,
                &request.target,
                &[("authorization", bearer(token().as_str()).as_str())],
                body,
                broker.services.clone(),
                VM_HTTP_READ_TIMEOUT,
            )
            .await;

            assert_eq!(
                response.status,
                VmHttpStatus::UpgradeRequired,
                "`{route}` served a guest that declared no contract version",
            );
            assert_eq!(
                (
                    broker.state.audit.table_row_count_for_test(request_table),
                    broker.state.audit.table_row_count_for_test(outcome_table),
                ),
                before,
                "`{route}` was refused but still wrote to `{request_table}` / `{outcome_table}`; \
                 a refusal happens before the effect, so it has nothing to record",
            );
        }
    }

    /// The request that exercises each route's audited effect. Every brokered
    /// route must appear; the panic is what a new capability trips.
    fn drive_for(
        route: &str,
        repo: &RepoRef,
        rev: &crate::vm_git_mirror_cache::GitCommitSha,
        run_id: AgentRunId,
    ) -> (VmHttpRequest, Vec<u8>) {
        let post = |target: &str, body: Vec<u8>| {
            (
                VmHttpRequest::new(
                    "POST",
                    target,
                    Some(bearer(token().as_str())),
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
                ),
                body,
            )
        };
        match route {
            "ClaudeProxy" => post(VM_CLAUDE_MESSAGES_PATH, b"{}".to_vec()),
            "OpenAiProxy" => post(VM_OPENAI_RESPONSES_PATH, b"{}".to_vec()),
            "NixCache" => (
                VmHttpRequest::new(
                    "GET",
                    "/v1/nix/cache/nix-cache-info",
                    Some(basic(&super::basic_authorization_value(
                        &session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap()),
                    ))),
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
                ),
                Vec::new(),
            ),
            "GitPush" => {
                let metadata = VmGitPushMetadata::new(
                    GitCloneRepo::new(repo.clone()).unwrap(),
                    GitBranchName::new("feature").unwrap(),
                    None,
                    GitObjectId::new("a".repeat(40)).unwrap(),
                );
                let body = encode_vm_git_push_request_body(
                    &VmGitPushRequest::new(metadata, b"bundle-bytes".to_vec()).unwrap(),
                )
                .unwrap();
                post(VM_GIT_PUSH_PATH, body)
            }
            "FlakeProvision" => post(
                VM_FLAKE_PROVISION_PATH,
                serde_json::to_vec(&VmFlakeProvisionRequest::new(
                    GitCloneRepo::new(repo.clone()).unwrap(),
                    rev.as_str().parse().unwrap(),
                ))
                .unwrap(),
            ),
            "AgentRunOutcome" => {
                let empty = AgentRunStreamUpload {
                    byte_len: 0,
                    sha256_hex: crate::agent_run::sha256_hex(b""),
                    truncated: false,
                    retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                    retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
                };
                post(
                    &vm_agent_run_outcome_path(run_id),
                    serde_json::to_vec(&VmAgentRunOutcomeUpload {
                        run_id,
                        status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
                        exit_code: 0,
                        stdout: empty.clone(),
                        stderr: empty,
                    })
                    .unwrap(),
                )
            }
            other => panic!(
                "brokered route `{other}` is not driven by the audit-pair oracle: add a request \
                 that exercises its effect, or the route escapes the invariant check",
            ),
        }
    }
}
