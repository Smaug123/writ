//! Tests for the guest-side `writ-vm` command surface (git clone/push bundle
//! flows, workspace warm, broker HTTP framing, temp-file lifecycles). Split out
//! of `lib.rs` (an inline `#[cfg(test)]` module) to keep the crate root
//! readable; the tests are unchanged.

use super::*;
use proptest::prelude::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn repo() -> GitCloneRepo {
    "owner/repo".parse().unwrap()
}

async fn serve_once(response: String) -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_for_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let read = stream.read(&mut buf).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&request);
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let body_start = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                while request.len() < body_start + content_length {
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

fn http_response(status: &str, content_type: &str, body: &[u8]) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
}

fn http_response_without_content_length(status: &str, content_type: &str, body: &[u8]) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
        String::from_utf8_lossy(body)
    )
}

fn write_fake_git(dir: &Path) -> PathBuf {
    let path = dir.join("fake-git");
    let log = dir.join("git.log");
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         printf '%s\\n' \"$*\" >> {log}\n\
         printf 'broker_url=%s\\n' \"${{WRIT_BROKER_URL-unset}}\" >> {log}\n\
         printf 'broker_token=%s\\n' \"${{WRIT_BROKER_TOKEN-unset}}\" >> {log}\n\
         if [ \"${{1:-}}\" = 'clone' ]; then\n\
         shift\n\
         test \"${{1:-}}\" = '--'\n\
         shift\n\
         bundle=\"$1\"\n\
         dest=\"$2\"\n\
         test -f \"$bundle\"\n\
         mkdir -p \"$dest/.git\"\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = 'init' ]; then\n\
         shift\n\
         test \"${{1:-}}\" = '--'\n\
         shift\n\
         mkdir -p \"$1/.git\"\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = '-C' ]; then\n\
         dest=\"$2\"\n\
         shift 2\n\
         if [ \"${{1:-}}\" = 'remote' ]; then\n\
         test \"${{2:-}}\" = 'add'\n\
         test \"${{3:-}}\" = 'origin'\n\
         test -n \"${{4:-}}\"\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = 'fetch' ]; then\n\
         shift\n\
         test \"${{1:-}}\" = '--'\n\
         shift\n\
         test -f \"$1\"\n\
         test -n \"$2\"\n\
         printf 'fetched=%s\\n' \"$2\" > \"$dest/FETCH_HEAD\"\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = 'checkout' ]; then\n\
         if [ \"${{2:-}}\" = '-B' ]; then\n\
         test \"${{3:-}}\" = 'main'\n\
         test \"${{4:-}}\" = 'refs/remotes/origin/main'\n\
         exit 0\n\
         fi\n\
         test \"${{2:-}}\" = '--detach'\n\
         test \"${{3:-}}\" = 'FETCH_HEAD'\n\
         test -f \"$dest/FETCH_HEAD\"\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = 'branch' ]; then\n\
         test \"${{2:-}}\" = '--set-upstream-to'\n\
         test \"${{3:-}}\" = 'origin/main'\n\
         test \"${{4:-}}\" = 'main'\n\
         exit 0\n\
         fi\n\
         if [ \"${{1:-}}\" = 'status' ]; then\n\
         test \"${{2:-}}\" = '--porcelain=v1'\n\
         exit 0\n\
         fi\n\
         fi\n\
         exit 64\n",
        log = shell_quote(&log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn leaked_bundle_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".writ-vm-"))
        .count()
}

fn required_test_tool(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("PATH must contain {name} for vm_client tests"));
    for dir in std::env::split_paths(&path) {
        let candidate = if dir.is_absolute() {
            dir.join(name)
        } else {
            std::env::current_dir().unwrap().join(dir).join(name)
        };
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("{name} not found on PATH for vm_client tests");
}

fn run_test_git(git: &Path, args: &[&str]) {
    let output = Command::new(git)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn get_session_json_gets_session_endpoint_with_bearer_token() {
    let body = br#"{"api":"writ-vm-http","version":1,"session_id":"test-session"}"#;
    let (broker_url, captured) =
        serve_once(http_response("200 OK", "application/json", body)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let session = get_session_json(&config).await.unwrap();

    assert_eq!(session["api"], "writ-vm-http");
    assert_eq!(session["version"], 1);
    assert_eq!(session["session_id"], "test-session");
    let request = captured.lock().unwrap().clone();
    assert!(request.starts_with("GET /v1/session HTTP/1.1"), "{request}");
    assert!(
        request.contains("authorization: Bearer writ-vm-secret")
            || request.contains("Authorization: Bearer writ-vm-secret"),
        "{request}"
    );
}

#[tokio::test]
async fn plain_text_broker_errors_are_preserved() {
    let (broker_url, _captured) = serve_once(http_response(
        "405 Method Not Allowed",
        "text/plain",
        b"method not allowed",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let err = get_session_json(&config).await.unwrap_err();

    assert!(matches!(
        err,
        VmClientError::BrokerHttp {
            status: 405,
            message
        } if message == "method not allowed"
    ));
}

#[tokio::test]
async fn fetch_agent_run_config_gets_one_run_config_with_bearer_token() {
    let run_id: AgentRunId = "00000000-0000-0000-0000-000000000501".parse().unwrap();
    let prompt = AgentPrompt::new("SECRET prompt");
    let body = serde_json::to_vec(&VmAgentRunConfigResponse::new(
        run_id,
        prompt.clone(),
        "gpt-5.4-mini",
    ))
    .unwrap();
    let (broker_url, captured) =
        serve_once(http_response("200 OK", "application/json", &body)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let (fetched_prompt, fetched_model) = fetch_agent_run_config(&config, run_id).await.unwrap();

    assert_eq!(fetched_prompt, prompt);
    assert_eq!(fetched_model, "gpt-5.4-mini");
    let request = captured.lock().unwrap().clone();
    assert!(
        request
            .starts_with("GET /v1/agent-runs/00000000-0000-0000-0000-000000000501/config HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("authorization: Bearer writ-vm-secret")
            || request.contains("Authorization: Bearer writ-vm-secret"),
        "{request}"
    );
    assert!(!format!("{fetched_prompt:?}").contains(prompt.as_str()));
}

#[tokio::test]
async fn upload_agent_run_outcome_posts_stream_metadata_and_retained_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let run_id: AgentRunId = "00000000-0000-0000-0000-000000000502".parse().unwrap();
    let stdout_path = dir.path().join("stdout.log");
    let stderr_path = dir.path().join("stderr.log");
    fs::write(&stdout_path, b"Hello from Claude\n").unwrap();
    fs::write(&stderr_path, b"").unwrap();
    let outcome = AgentRunOutcome {
        run_id,
        status: writ_agent_run::AgentRunTerminalStatus::Succeeded,
        exit_code: 0,
        stdout: AgentRunStreamSummary {
            path: stdout_path,
            byte_len: 18,
            sha256_hex: writ_agent_run::sha256_hex(b"Hello from Claude\n"),
            truncated: false,
        },
        stderr: AgentRunStreamSummary {
            path: stderr_path,
            byte_len: 0,
            sha256_hex: writ_agent_run::sha256_hex(b""),
            truncated: false,
        },
    };
    let (broker_url, captured) = serve_once(http_response("200 OK", "text/plain", b"ok")).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    upload_agent_run_outcome(&config, &outcome).await.unwrap();

    let request = captured.lock().unwrap().clone();
    assert!(
        request.starts_with(
            "POST /v1/agent-runs/00000000-0000-0000-0000-000000000502/outcome HTTP/1.1"
        ),
        "{request}"
    );
    assert!(
        request.contains("authorization: Bearer writ-vm-secret")
            || request.contains("Authorization: Bearer writ-vm-secret"),
        "{request}"
    );
    assert!(request.contains(r#""exit_code":0"#), "{request}");
    assert!(
        request.contains(r#""retained_base64":"SGVsbG8gZnJvbSBDbGF1ZGUK""#),
        "{request}"
    );
    assert!(!request.contains("Hello from Claude"), "{request}");
}

#[tokio::test]
async fn clone_from_broker_posts_request_and_clones_returned_bundle_without_token_in_git_argv() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let bundle = b"bundle bytes";
    let (broker_url, captured) = serve_once(http_response(
        "200 OK",
        "application/x-git-bundle; charset=utf-8",
        bundle,
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let destination = dir.path().join("checkout");
    let command = VmGitCloneCommand::new(
        repo(),
        Some("refs/heads/main".parse().unwrap()),
        Some(destination.clone()),
        git,
    )
    .unwrap();

    let cloned = clone_from_broker(&config, &command).await.unwrap();

    assert_eq!(cloned, destination);
    assert!(destination.join(".git").is_dir());
    let request = captured.lock().unwrap().clone();
    assert!(
        request.starts_with("POST /v1/git/clone HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("authorization: Bearer writ-vm-secret")
            || request.contains("Authorization: Bearer writ-vm-secret"),
        "{request}"
    );
    assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
    assert!(request.contains(r#""ref":"refs/heads/main""#), "{request}");

    let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
    assert!(git_log.contains("init -- "), "{git_log}");
    assert!(
        git_log.contains("fetch -- ") && git_log.contains(" refs/heads/main"),
        "{git_log}"
    );
    assert!(
        git_log.contains("checkout --detach FETCH_HEAD"),
        "{git_log}"
    );
    assert!(!git_log.contains("--branch"), "{git_log}");
    assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
    assert!(git_log.contains("broker_url=unset"), "{git_log}");
    assert!(git_log.contains("broker_token=unset"), "{git_log}");
    assert_eq!(leaked_bundle_count(dir.path()), 0);
}

#[tokio::test]
async fn clone_from_broker_rejects_bundle_larger_than_client_limit_before_running_git() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let bundle = b"bundle bytes";
    let (broker_url, _captured) =
        serve_once(http_response("200 OK", "application/x-git-bundle", bundle)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret")
        .unwrap()
        .with_max_bundle_bytes(4)
        .unwrap();
    let command =
        VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

    let err = clone_from_broker(&config, &command).await.unwrap_err();

    assert!(matches!(
        err,
        VmClientError::BundleTooLarge {
            bytes,
            max_bundle_bytes: 4,
        } if bytes == u64::try_from(bundle.len()).unwrap()
    ));
    assert!(!dir.path().join("git.log").exists());
    assert_eq!(leaked_bundle_count(dir.path()), 0);
}

#[tokio::test]
async fn clone_from_broker_counts_streamed_bundle_bytes_when_length_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let bundle = b"bundle bytes";
    let (broker_url, _captured) = serve_once(http_response_without_content_length(
        "200 OK",
        "application/x-git-bundle",
        bundle,
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret")
        .unwrap()
        .with_max_bundle_bytes(4)
        .unwrap();
    let command =
        VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

    let err = clone_from_broker(&config, &command).await.unwrap_err();

    assert!(matches!(
        err,
        VmClientError::BundleTooLarge {
            bytes,
            max_bundle_bytes: 4,
        } if bytes == u64::try_from(bundle.len()).unwrap()
    ));
    assert!(!dir.path().join("git.log").exists());
    assert_eq!(leaked_bundle_count(dir.path()), 0);
}

#[test]
fn clone_bundle_with_real_git_supports_full_head_refs_from_bundles() {
    let dir = tempfile::tempdir().unwrap();
    let git = required_test_tool("git");
    let source = dir.path().join("source");
    let bundle = dir.path().join("main.bundle");
    let checkout_parent = tempfile::tempdir().unwrap();
    let relative_checkout = PathBuf::from("checkout");

    let source_arg = source.to_str().unwrap();
    run_test_git(&git, &["init", "--", source_arg]);
    run_test_git(
        &git,
        &["-C", source_arg, "config", "user.email", "a@example.com"],
    );
    run_test_git(&git, &["-C", source_arg, "config", "user.name", "a"]);
    run_test_git(
        &git,
        &["-C", source_arg, "config", "commit.gpgsign", "false"],
    );
    fs::write(source.join("file.txt"), "hello\n").unwrap();
    run_test_git(&git, &["-C", source_arg, "add", "file.txt"]);
    run_test_git(&git, &["-C", source_arg, "commit", "-m", "init"]);
    run_test_git(&git, &["-C", source_arg, "branch", "-M", "main"]);
    run_test_git(
        &git,
        &[
            "-C",
            source_arg,
            "bundle",
            "create",
            bundle.to_str().unwrap(),
            "refs/heads/main",
        ],
    );

    clone_bundle_with_git_from_cwd(
        &git,
        Some(&"refs/heads/main".parse().unwrap()),
        &relative_checkout,
        &fs::read(&bundle).unwrap(),
        checkout_parent.path(),
    )
    .unwrap();
    let checkout = checkout_parent.path().join(&relative_checkout);

    assert_eq!(
        fs::read_to_string(checkout.join("file.txt")).unwrap(),
        "hello\n"
    );
    let head = Command::new(&git)
        .args([
            "-C",
            checkout.to_str().unwrap(),
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert!(head.status.success());
    assert_eq!(String::from_utf8_lossy(&head.stdout).trim(), "HEAD");
}

fn commit_one_file(git: &Path, repo_dir: &Path) -> String {
    let arg = repo_dir.to_str().unwrap();
    run_test_git(git, &["init", "--", arg]);
    run_test_git(git, &["-C", arg, "config", "user.email", "a@example.com"]);
    run_test_git(git, &["-C", arg, "config", "user.name", "a"]);
    run_test_git(git, &["-C", arg, "config", "commit.gpgsign", "false"]);
    fs::write(repo_dir.join("flake.nix"), "{}\n").unwrap();
    run_test_git(git, &["-C", arg, "add", "."]);
    run_test_git(git, &["-C", arg, "commit", "-m", "init"]);
    let head = Command::new(git)
        .args(["-C", arg, "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(head.status.success());
    String::from_utf8_lossy(&head.stdout).trim().to_string()
}

fn provision_request() -> VmFlakeProvisionRequest {
    VmFlakeProvisionRequest::new(
        repo(),
        "0123456789abcdef0123456789abcdef01234567".parse().unwrap(),
    )
}

#[test]
fn resolve_head_object_id_returns_the_checked_out_commit() {
    let dir = tempfile::tempdir().unwrap();
    let git = required_test_tool("git");
    let repo_dir = dir.path().join("repo");
    let expected = commit_one_file(&git, &repo_dir);

    let rev = resolve_head_object_id(&git, &repo_dir).unwrap();

    assert_eq!(rev.as_str(), expected);
}

#[tokio::test]
async fn provision_best_effort_posts_repo_and_resolved_rev() {
    let dir = tempfile::tempdir().unwrap();
    let git = required_test_tool("git");
    let repo_dir = dir.path().join("repo");
    let rev = commit_one_file(&git, &repo_dir);

    let body = br#"{"status":"provisioned","request_id":"00000000-0000-0000-0000-000000000001","input_count":2,"archived_path_count":5,"archived_bytes":1024}"#;
    let (broker_url, captured) =
        serve_once(http_response("200 OK", "application/json", body)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmWorkspaceInitCommand::new(
        repo(),
        Some(repo_dir),
        WorkspaceWarmMode::Sources,
        git,
        "nix",
        None,
    )
    .unwrap();

    provision_flake_inputs_best_effort(&config, &command).await;

    let request = captured.lock().unwrap().clone();
    assert!(
        request.starts_with("POST /v1/nix/flake/provision "),
        "{request}"
    );
    assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
    assert!(request.contains(&format!(r#""rev":"{rev}""#)), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer writ-vm-secret"),
        "{request}"
    );
}

#[tokio::test]
async fn provision_best_effort_skips_when_warm_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let git = required_test_tool("git");
    let repo_dir = dir.path().join("repo");
    commit_one_file(&git, &repo_dir);
    let (broker_url, captured) = serve_once(http_response(
        "200 OK",
        "application/json",
        br#"{"status":"mirror_not_cached"}"#,
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmWorkspaceInitCommand::new(
        repo(),
        Some(repo_dir),
        WorkspaceWarmMode::None,
        git,
        "nix",
        None,
    )
    .unwrap();

    provision_flake_inputs_best_effort(&config, &command).await;

    // No warm step will run, so nothing is provisioned and the broker is
    // never contacted.
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn post_flake_provision_reads_mirror_not_cached() {
    let (broker_url, _captured) = serve_once(http_response(
        "200 OK",
        "application/json",
        br#"{"status":"mirror_not_cached"}"#,
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let outcome = post_flake_provision(&config, &provision_request())
        .await
        .unwrap();

    assert_eq!(outcome, VmFlakeProvisionResponse::MirrorNotCached);
}

#[tokio::test]
async fn post_flake_provision_classifies_a_structured_refusal() {
    let body =
        br#"{"error":"unprovisionable","message":"the repository has no committed flake.lock"}"#;
    let (broker_url, _captured) = serve_once(http_response(
        "422 Unprocessable Content",
        "application/json",
        body,
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let err = post_flake_provision(&config, &provision_request())
        .await
        .unwrap_err();

    match err {
        FlakeProvisionDegrade::Status { code, message } => {
            assert_eq!(code, 422);
            assert_eq!(
                message.as_deref(),
                Some("the repository has no committed flake.lock")
            );
        }
        other => panic!("expected a Status degrade, got {other:?}"),
    }
}

#[tokio::test]
async fn post_flake_provision_tolerates_a_plain_text_disabled_endpoint() {
    let (broker_url, _captured) =
        serve_once(http_response("404 Not Found", "text/plain", b"not found")).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

    let err = post_flake_provision(&config, &provision_request())
        .await
        .unwrap_err();

    match err {
        FlakeProvisionDegrade::Status { code, message } => {
            assert_eq!(code, 404);
            assert_eq!(message, None);
        }
        other => panic!("expected a Status degrade, got {other:?}"),
    }
}

#[test]
fn workspace_init_creates_clean_main_branch_tracking_origin_from_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let git = required_test_tool("git");
    let source = dir.path().join("source");
    let bundle = dir.path().join("main.bundle");
    let checkout = dir.path().join("checkout");

    let source_arg = source.to_str().unwrap();
    run_test_git(&git, &["init", "--", source_arg]);
    run_test_git(
        &git,
        &["-C", source_arg, "config", "user.email", "a@example.com"],
    );
    run_test_git(&git, &["-C", source_arg, "config", "user.name", "a"]);
    run_test_git(
        &git,
        &["-C", source_arg, "config", "commit.gpgsign", "false"],
    );
    fs::write(source.join("file.txt"), "hello\n").unwrap();
    run_test_git(&git, &["-C", source_arg, "add", "file.txt"]);
    run_test_git(&git, &["-C", source_arg, "commit", "-m", "init"]);
    run_test_git(&git, &["-C", source_arg, "branch", "-M", "main"]);
    run_test_git(
        &git,
        &[
            "-C",
            source_arg,
            "bundle",
            "create",
            bundle.to_str().unwrap(),
            "refs/heads/main",
        ],
    );

    init_workspace_from_bundle_with_git_from_cwd(
        &git,
        &repo(),
        &checkout,
        &fs::read(&bundle).unwrap(),
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(checkout.join("file.txt")).unwrap(),
        "hello\n"
    );
    let branch = Command::new(&git)
        .args([
            "-C",
            checkout.to_str().unwrap(),
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert!(branch.status.success());
    assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
    let upstream = Command::new(&git)
        .args([
            "-C",
            checkout.to_str().unwrap(),
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{u}",
        ])
        .output()
        .unwrap();
    assert!(upstream.status.success());
    assert_eq!(
        String::from_utf8_lossy(&upstream.stdout).trim(),
        "origin/main"
    );
    let status = Command::new(&git)
        .args(["-C", checkout.to_str().unwrap(), "status", "--porcelain=v1"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(String::from_utf8_lossy(&status.stdout).trim(), "");
}

#[tokio::test]
async fn workspace_init_from_broker_posts_main_ref_and_does_not_leak_token_to_git() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let (broker_url, captured) = serve_once(http_response(
        "200 OK",
        "application/x-git-bundle",
        b"bundle bytes",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let checkout = dir.path().join("checkout");
    let command = VmWorkspaceInitCommand::new(
        repo(),
        Some(checkout.clone()),
        WorkspaceWarmMode::None,
        git,
        "nix",
        None,
    )
    .unwrap();

    let initialized = init_workspace_from_broker(&config, &command).await.unwrap();

    assert_eq!(initialized, checkout);
    let request = captured.lock().unwrap().clone();
    assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
    assert!(request.contains(r#""ref":"refs/heads/main""#), "{request}");
    let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
    assert!(
        git_log.contains("fetch -- ")
            && git_log.contains("refs/heads/main:refs/remotes/origin/main"),
        "{git_log}"
    );
    assert!(
        git_log.contains("remote add origin https://github.com/owner/repo.git"),
        "{git_log}"
    );
    assert!(
        git_log.contains("checkout -B main refs/remotes/origin/main"),
        "{git_log}"
    );
    assert!(
        git_log.contains("branch --set-upstream-to origin/main main"),
        "{git_log}"
    );
    assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
    assert!(git_log.contains("broker_url=unset"), "{git_log}");
    assert!(git_log.contains("broker_token=unset"), "{git_log}");
}

/// A fake `nix` that logs each invocation's argv (one line per call) and
/// succeeds, so warm tests can pin the exact argument envelope.
fn write_fake_nix(dir: &Path) -> PathBuf {
    let path = dir.join("fake-nix");
    let log = dir.join("nix.log");
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> {log}\nexit 0\n",
        log = log.display()
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn warm_command(
    dir: &Path,
    warm: WorkspaceWarmMode,
    prewarm_substituter_url: Option<String>,
) -> VmWorkspaceInitCommand {
    let destination = dir.join("checkout");
    fs::create_dir_all(&destination).unwrap();
    VmWorkspaceInitCommand::new(
        repo(),
        Some(destination),
        warm,
        "git",
        write_fake_nix(dir),
        prewarm_substituter_url,
    )
    .unwrap()
}

const TEST_PREWARM_URL: &str = "http://192.168.252.1:51375/v1/nix/prewarm";

#[test]
fn devshell_warm_pins_both_steps_to_the_prewarm_substituter() {
    let dir = tempfile::tempdir().unwrap();
    let command = warm_command(
        dir.path(),
        WorkspaceWarmMode::DevShell,
        Some(TEST_PREWARM_URL.to_string()),
    );

    warm_workspace(&command).unwrap();

    let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
    let calls: Vec<&str> = nix_log.lines().collect();
    assert_eq!(calls.len(), 2, "{nix_log}");
    let override_prefix = format!("--option substituters {TEST_PREWARM_URL} ");
    // The strict guarantee covers the *whole* warm: eval input fetches
    // (flake metadata) and closure realisation alike.
    assert!(calls[0].starts_with(&override_prefix), "{nix_log}");
    assert!(calls[0].contains("flake metadata"), "{nix_log}");
    assert!(calls[1].starts_with(&override_prefix), "{nix_log}");
    // Strict realisation is `print-dev-env`, never `nix develop`: develop
    // additionally resolves nixpkgs#bashInteractive, which is outside the
    // pre-warmed closure and unservable by the strict substituter.
    assert!(calls[1].contains("print-dev-env"), "{nix_log}");
    assert!(!calls[1].contains(" develop "), "{nix_log}");
}

#[test]
fn devshell_warm_without_prewarm_url_keeps_session_default_substituters() {
    let dir = tempfile::tempdir().unwrap();
    let command = warm_command(dir.path(), WorkspaceWarmMode::DevShell, None);

    warm_workspace(&command).unwrap();

    let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
    let calls: Vec<&str> = nix_log.lines().collect();
    assert_eq!(calls.len(), 2, "{nix_log}");
    assert!(
        !nix_log.contains("substituters"),
        "no pre-warm URL means no substituter override: {nix_log}"
    );
    // The non-strict warm keeps `nix develop --command true` byte-for-byte
    // (the shell substitutes through the upstream-capable proxy as before).
    assert!(calls[1].contains("develop"), "{nix_log}");
    assert!(!calls[1].contains("print-dev-env"), "{nix_log}");
}

#[test]
fn sources_warm_stays_on_the_session_default_substituters() {
    // Strictness is the devShell warm's contract; a sources-only warm keeps
    // the proxied default even when the daemon advertised the pre-warm URL.
    let dir = tempfile::tempdir().unwrap();
    let command = warm_command(
        dir.path(),
        WorkspaceWarmMode::Sources,
        Some(TEST_PREWARM_URL.to_string()),
    );

    warm_workspace(&command).unwrap();

    let nix_log = fs::read_to_string(dir.path().join("nix.log")).unwrap();
    assert_eq!(nix_log.lines().count(), 1, "{nix_log}");
    assert!(!nix_log.contains("substituters"), "{nix_log}");
}

#[test]
fn workspace_init_command_rejects_a_non_http_prewarm_substituter_url() {
    let err = VmWorkspaceInitCommand::new(
        repo(),
        Some(PathBuf::from("/workspace/repo")),
        WorkspaceWarmMode::DevShell,
        "git",
        "nix",
        Some("file:///srv/prewarm".to_string()),
    )
    .unwrap_err();

    assert_eq!(
        err,
        VmWorkspaceInitCommandError::UnsupportedPrewarmSubstituterUrl(
            "file:///srv/prewarm".to_string()
        )
    );
}

#[tokio::test]
async fn clone_from_broker_ref_path_rejects_existing_destination_before_git_init() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let destination = dir.path().join("checkout");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("keep.txt"), "do not overwrite\n").unwrap();
    let (broker_url, _captured) = serve_once(http_response(
        "200 OK",
        "application/x-git-bundle",
        b"bundle bytes",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitCloneCommand::new(
        repo(),
        Some("refs/heads/main".parse().unwrap()),
        Some(destination.clone()),
        git,
    )
    .unwrap();

    let err = clone_from_broker(&config, &command).await.unwrap_err();

    assert!(matches!(err, VmClientError::DestinationAlreadyExists(path) if path == destination));
    assert_eq!(
        fs::read_to_string(destination.join("keep.txt")).unwrap(),
        "do not overwrite\n"
    );
    assert!(!dir.path().join("git.log").exists());
    assert_eq!(leaked_bundle_count(dir.path()), 0);
}

#[tokio::test]
async fn clone_from_broker_does_not_run_git_when_broker_denies_request() {
    let dir = tempfile::tempdir().unwrap();
    let git = write_fake_git(dir.path());
    let body = br#"{"error":"denied","message":"not allowed"}"#;
    let (broker_url, _captured) =
        serve_once(http_response("403 Forbidden", "application/json", body)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command =
        VmGitCloneCommand::new(repo(), None, Some(dir.path().join("checkout")), git).unwrap();

    let err = clone_from_broker(&config, &command).await.unwrap_err();

    assert!(matches!(
        err,
        VmClientError::BrokerHttp {
            status: 403,
            message
        } if message == "not allowed"
    ));
    assert!(!dir.path().join("git.log").exists());
    assert_eq!(leaked_bundle_count(dir.path()), 0);
}

#[test]
fn clone_command_defaults_destination_to_repo_name() {
    let command = VmGitCloneCommand::new(repo(), None, None, "git").unwrap();
    assert_eq!(command.destination(), Path::new("repo"));
}

#[test]
fn client_config_debug_redacts_broker_token() {
    let config = VmClientConfig::new("http://192.168.252.1:18080", "writ-vm-secret").unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains("writ-vm-secret"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

#[test]
fn broker_token_rejects_header_unsafe_values() {
    assert!(matches!(
        VmClientConfig::new("http://192.168.252.1:18080", "has space"),
        Err(VmClientConfigError::InvalidToken)
    ));
    assert!(matches!(
        VmClientConfig::new("http://192.168.252.1:18080", "has\nnewline"),
        Err(VmClientConfigError::InvalidToken)
    ));
    for token in ["has+plus", "has/slash", "has=equals", "has:colon", "has@at"] {
        assert!(
            matches!(
                VmClientConfig::new("http://192.168.252.1:18080", token),
                Err(VmClientConfigError::InvalidToken)
            ),
            "accepted {token:?}"
        );
    }
}

fn valid_owner() -> impl Strategy<Value = String> {
    prop_oneof!["[A-Za-z0-9]", "[A-Za-z0-9][A-Za-z0-9-]{0,37}[A-Za-z0-9]",]
}

fn valid_repo_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}".prop_filter("not dot-only or .git-suffixed", |name| {
        !matches!(name.as_str(), "." | "..") && !name.ends_with(".git")
    })
}

fn write_fake_git_push(
    dir: &Path,
    rev_parse_oid: &str,
    bundle_bytes: &[u8],
    bundle_list_heads: &str,
) -> PathBuf {
    let bundle_payload = dir.join("bundle_payload");
    fs::write(&bundle_payload, bundle_bytes).unwrap();
    let list_heads_payload = dir.join("bundle_list_heads");
    // Newline-terminate so single-line outputs match the standard `git
    // bundle list-heads` format.
    let list_heads_text = if bundle_list_heads.is_empty() {
        String::new()
    } else {
        format!("{bundle_list_heads}\n")
    };
    fs::write(&list_heads_payload, list_heads_text).unwrap();
    let log = dir.join("git.log");
    let path = dir.join("fake-git-push");
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         printf '%s\\n' \"$*\" >> {log}\n\
         printf 'broker_url=%s\\n' \"${{WRIT_BROKER_URL-unset}}\" >> {log}\n\
         printf 'broker_token=%s\\n' \"${{WRIT_BROKER_TOKEN-unset}}\" >> {log}\n\
         if [ \"${{1:-}}\" = '-C' ]; then\n\
         printf 'cwd=%s\\n' \"$2\" >> {log}\n\
         shift 2\n\
         fi\n\
         case \"${{1:-}}\" in\n\
         rev-parse)\n\
         printf '%s\\n' '{oid}'\n\
         exit 0\n\
         ;;\n\
         bundle)\n\
         shift\n\
         case \"${{1:-}}\" in\n\
         create)\n\
         shift\n\
         out_path=\"$1\"\n\
         cp {payload} \"$out_path\"\n\
         exit 0\n\
         ;;\n\
         list-heads)\n\
         cat {list_heads}\n\
         exit 0\n\
         ;;\n\
         esac\n\
         ;;\n\
         esac\n\
         exit 64\n",
        log = shell_quote(&log),
        payload = shell_quote(&bundle_payload),
        list_heads = shell_quote(&list_heads_payload),
        oid = rev_parse_oid,
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn list_heads_line(oid: &str, branch: &str) -> String {
    format!("{oid} refs/heads/{branch}")
}

fn fake_oid(nibble: char) -> String {
    std::iter::repeat_n(nibble, 40).collect()
}

fn parse_oid(raw: &str) -> writ_vm_git::GitObjectId {
    raw.parse().unwrap()
}

fn parse_branch(raw: &str) -> writ_vm_git::GitBranchName {
    raw.parse().unwrap()
}

fn receipt_json(
    repo: &str,
    branch: &str,
    new_head: &str,
    expected_remote_head: Option<&str>,
    push_request_id: &str,
    staged_at_ms: u64,
) -> String {
    let expected = match expected_remote_head {
        Some(oid) => format!("\"{oid}\""),
        None => "null".to_string(),
    };
    format!(
        "{{\"repo\":\"{repo}\",\"branch\":\"{branch}\",\
         \"expected_remote_head\":{expected},\"new_head\":\"{new_head}\",\
         \"push_request_id\":\"{push_request_id}\",\"staged_at\":{staged_at_ms}}}"
    )
}

#[tokio::test]
async fn push_to_broker_posts_bundle_with_metadata_and_returns_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('b');
    let expected_head = fake_oid('a');
    let bundle_bytes = b"PACK push bundle";
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        bundle_bytes,
        &list_heads_line(&new_head, "feature/x"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let body = receipt_json(
        "owner/repo",
        "feature/x",
        &new_head,
        Some(&expected_head),
        "00000000-0000-0000-0000-000000000601",
        1_700_000_000_000,
    );
    let (broker_url, captured) =
        serve_once(http_response("200 OK", "application/json", body.as_bytes())).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&expected_head)),
        workdir.clone(),
        git,
    )
    .unwrap();

    let receipt = push_to_broker(&config, &command).await.unwrap();

    assert_eq!(receipt.repo().to_string(), "owner/repo");
    assert_eq!(receipt.branch().as_str(), "feature/x");
    assert_eq!(receipt.new_head().as_str(), new_head);
    assert_eq!(
        receipt.expected_remote_head().map(|oid| oid.as_str()),
        Some(expected_head.as_str())
    );

    let request = captured.lock().unwrap().clone();
    assert!(
        request.starts_with("POST /v1/git/push HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("authorization: Bearer writ-vm-secret")
            || request.contains("Authorization: Bearer writ-vm-secret"),
        "{request}"
    );
    assert!(
        request.contains("application/vnd.writ.git-push-bundle"),
        "{request}"
    );
    assert!(request.contains(r#""repo":"owner/repo""#), "{request}");
    assert!(request.contains(r#""branch":"feature/x""#), "{request}");
    assert!(
        request.contains(&format!(r#""new_head":"{new_head}""#)),
        "{request}"
    );
    assert!(
        request.contains(&format!(r#""expected_remote_head":"{expected_head}""#)),
        "{request}"
    );

    let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
    assert!(
        git_log.contains("rev-parse --verify refs/heads/feature/x^{commit}"),
        "{git_log}"
    );
    assert!(
        git_log.contains("bundle create ") && git_log.contains("refs/heads/feature/x"),
        "{git_log}"
    );
    assert!(
        git_log.contains(&format!("--not {expected_head}")),
        "{git_log}"
    );
    assert!(!git_log.contains("writ-vm-secret"), "{git_log}");
    assert!(git_log.contains("broker_url=unset"), "{git_log}");
    assert!(git_log.contains("broker_token=unset"), "{git_log}");
}

#[tokio::test]
async fn push_to_broker_omits_not_arg_when_creating_a_branch() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('c');
    let bundle_bytes = b"PACK create bundle";
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        bundle_bytes,
        &list_heads_line(&new_head, "feature/new"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let body = receipt_json(
        "owner/repo",
        "feature/new",
        &new_head,
        None,
        "00000000-0000-0000-0000-000000000602",
        1_700_000_000_000,
    );
    let (broker_url, captured) =
        serve_once(http_response("200 OK", "application/json", body.as_bytes())).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/new"),
        parse_oid(&new_head),
        None,
        workdir,
        git,
    )
    .unwrap();

    let receipt = push_to_broker(&config, &command).await.unwrap();

    assert!(receipt.expected_remote_head().is_none());
    let request = captured.lock().unwrap().clone();
    assert!(
        request.contains(r#""expected_remote_head":null"#),
        "{request}"
    );
    let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
    assert!(!git_log.contains("--not "), "{git_log}");
}

#[tokio::test]
async fn push_to_broker_rejects_branch_head_mismatch_before_bundling() {
    let dir = tempfile::tempdir().unwrap();
    let claimed_head = fake_oid('b');
    let actual_head = fake_oid('d');
    let git = write_fake_git_push(dir.path(), &actual_head, b"PACK should not be sent", "");
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    // The broker mock should never be reached, but bind a listener so we
    // observe whether the client tried to send anything.
    let (broker_url, captured) = serve_once(http_response(
        "500 Internal Server Error",
        "text/plain",
        b"unexpected request",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&claimed_head),
        Some(parse_oid(&fake_oid('a'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    match err {
        VmClientError::BranchHeadMismatch {
            branch,
            expected,
            actual,
        } => {
            assert_eq!(branch, "feature/x");
            assert_eq!(expected, claimed_head);
            assert_eq!(actual, actual_head);
        }
        other => panic!("expected BranchHeadMismatch, got {other:?}"),
    }
    // No bundle command should have been spawned.
    let git_log = fs::read_to_string(dir.path().join("git.log")).unwrap();
    assert!(!git_log.contains("bundle create"), "{git_log}");
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn push_to_broker_rejects_oversized_bundle_before_posting() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('e');
    // Bundle larger than the configured cap.
    let bundle_bytes = vec![0u8; 256];
    let git = write_fake_git_push(dir.path(), &new_head, &bundle_bytes, "");
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let (broker_url, captured) = serve_once(http_response(
        "500 Internal Server Error",
        "text/plain",
        b"unexpected request",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret")
        .unwrap()
        .with_max_bundle_bytes(64)
        .unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&fake_oid('a'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    assert!(matches!(
        err,
        VmClientError::BundleTooLarge {
            bytes: 256,
            max_bundle_bytes: 64,
        }
    ));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn push_to_broker_surfaces_broker_error_message_from_push_error_response() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('f');
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        b"PACK denied bundle",
        &list_heads_line(&new_head, "feature/x"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let body = br#"{"error":"denied","message":"session is closed"}"#;
    let (broker_url, _captured) =
        serve_once(http_response("410 Gone", "application/json", body)).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&fake_oid('a'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    match err {
        VmClientError::BrokerHttp { status, message } => {
            assert_eq!(status, 410);
            assert_eq!(message, "session is closed");
        }
        other => panic!("expected BrokerHttp, got {other:?}"),
    }
}

#[tokio::test]
async fn push_to_broker_returns_invalid_receipt_error_for_malformed_response_body() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('a');
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        b"PACK valid bundle",
        &list_heads_line(&new_head, "feature/x"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let (broker_url, _captured) =
        serve_once(http_response("200 OK", "application/json", b"not json")).await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&fake_oid('b'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    assert!(
        matches!(err, VmClientError::BrokerInvalidReceipt(_)),
        "got {err:?}"
    );
}

#[test]
fn temp_bundle_path_uses_a_private_parent_directory() {
    use std::os::unix::fs::PermissionsExt;

    let bundle = TempBundlePath::reserve().unwrap();
    let parent = bundle
        .path()
        .parent()
        .expect("bundle path must live in a directory")
        .to_path_buf();

    let metadata = fs::metadata(&parent).unwrap();
    assert!(metadata.is_dir(), "{parent:?} should be a directory");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "expected 0700 on {parent:?}, got {mode:o}");

    drop(bundle);
    assert!(
        !parent.exists(),
        "temp bundle directory {parent:?} was not cleaned up on drop"
    );
}

#[test]
fn temp_bundle_path_is_absolute_even_under_relative_temp_root() {
    // The reserve() postcondition: the bundle path is absolute, so handing
    // it to `git -C <workdir>` does not resolve it under <workdir>.
    let bundle = TempBundlePath::reserve().unwrap();
    assert!(
        bundle.path().is_absolute(),
        "bundle path {:?} should be absolute",
        bundle.path()
    );
}

#[test]
fn absolutize_temp_root_passes_through_absolute_paths() {
    let abs = std::env::temp_dir();
    assert!(abs.is_absolute(), "test precondition: temp_dir is absolute");
    let resolved = absolutize_temp_root(abs.clone()).unwrap();
    assert_eq!(resolved, abs);
}

#[test]
fn absolutize_temp_root_prepends_cwd_for_relative_paths() {
    let resolved = absolutize_temp_root(PathBuf::from("relative/tmp")).unwrap();
    assert!(resolved.is_absolute(), "{resolved:?} should be absolute");
    assert!(
        resolved.ends_with("relative/tmp"),
        "{resolved:?} should end with the original relative tail"
    );
}

#[test]
fn configure_push_git_env_strips_every_repo_selection_var() {
    use std::ffi::OsStr;

    let mut command = Command::new("git");
    // Pre-set every repo-selection var so we can verify the helper
    // overrides each one with an env_remove (recorded by get_envs() as
    // `(name, None)`).
    for var in GIT_REPO_SELECTION_ENV {
        command.env(var, "/tmp/should-be-cleared");
    }
    configure_push_git_env(&mut command);

    let registered: std::collections::HashMap<&OsStr, Option<&OsStr>> =
        command.get_envs().collect();
    for var in GIT_REPO_SELECTION_ENV {
        let key = OsStr::new(var);
        assert!(
            matches!(registered.get(key), Some(None)),
            "{var} should be marked for removal"
        );
    }
    // GIT_TERMINAL_PROMPT is set positively; it is not a repo-selection
    // override, so it's not listed in GIT_REPO_SELECTION_ENV.
    assert_eq!(
        registered.get(OsStr::new("GIT_TERMINAL_PROMPT")),
        Some(&Some(OsStr::new("0")))
    );
}

#[tokio::test]
async fn push_to_broker_rejects_bundle_advertising_a_different_head() {
    // Simulates a TOCTOU race: rev-parse returns new_head, but bundle
    // list-heads (i.e. what `git bundle create` actually packed) advertises
    // a different oid for the branch ref. The push must be rejected before
    // posting to the broker.
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('b');
    let drifted_head = fake_oid('d');
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        b"PACK drifted bundle",
        &list_heads_line(&drifted_head, "feature/x"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let (broker_url, captured) = serve_once(http_response(
        "500 Internal Server Error",
        "text/plain",
        b"unexpected request",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&fake_oid('a'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    match err {
        VmClientError::BundleHeadMismatch {
            branch,
            ref_name,
            expected,
            actual,
        } => {
            assert_eq!(branch, "feature/x");
            assert_eq!(ref_name, "refs/heads/feature/x");
            assert_eq!(expected, new_head);
            assert_eq!(actual, drifted_head);
        }
        other => panic!("expected BundleHeadMismatch, got {other:?}"),
    }
    assert!(
        captured.lock().unwrap().is_empty(),
        "broker should not be contacted when the bundle disagrees with new_head"
    );
}

#[tokio::test]
async fn push_to_broker_rejects_bundle_missing_branch_ref() {
    // The bundle's ref list does not mention refs/heads/<branch> at all.
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('b');
    let git = write_fake_git_push(
        dir.path(),
        &new_head,
        b"PACK refless bundle",
        &list_heads_line(&new_head, "other-branch"),
    );
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let (broker_url, captured) = serve_once(http_response(
        "500 Internal Server Error",
        "text/plain",
        b"unexpected request",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        Some(parse_oid(&fake_oid('a'))),
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    match err {
        VmClientError::BundleMissingBranch { branch, ref_name } => {
            assert_eq!(branch, "feature/x");
            assert_eq!(ref_name, "refs/heads/feature/x");
        }
        other => panic!("expected BundleMissingBranch, got {other:?}"),
    }
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn push_to_broker_rejects_empty_bundle_with_dedicated_error() {
    let dir = tempfile::tempdir().unwrap();
    let new_head = fake_oid('a');
    let git = write_fake_git_push(dir.path(), &new_head, b"", "");
    let workdir = dir.path().join("repo");
    fs::create_dir_all(&workdir).unwrap();

    let (broker_url, captured) = serve_once(http_response(
        "500 Internal Server Error",
        "text/plain",
        b"unexpected request",
    ))
    .await;
    let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();
    let command = VmGitPushCommand::new(
        repo(),
        parse_branch("feature/x"),
        parse_oid(&new_head),
        None,
        workdir,
        git,
    )
    .unwrap();

    let err = push_to_broker(&config, &command).await.unwrap_err();

    match err {
        VmClientError::BundleEmpty { branch } => assert_eq!(branch, "feature/x"),
        other => panic!("expected BundleEmpty, got {other:?}"),
    }
    assert!(captured.lock().unwrap().is_empty());
}

proptest! {
    #[test]
    fn clone_command_default_destination_is_repo_name(owner in valid_owner(), name in valid_repo_name()) {
        let repo: GitCloneRepo = format!("{owner}/{name}").parse().unwrap();

        let command = VmGitCloneCommand::new(repo, None, None, "git").unwrap();

        prop_assert_eq!(command.destination(), Path::new(&name));
    }

    #[test]
    fn broker_token_debug_never_contains_secret(hex in "[A-F0-9]{16,64}") {
        let token = format!("secret_{hex}");
        let config = VmClientConfig::new("http://192.168.252.1:18080", token.clone()).unwrap();

        let debug = format!("{config:?}");

        prop_assert!(!debug.contains(&token), "{debug}");
        prop_assert!(debug.contains("<redacted>"), "{debug}");
    }
}
