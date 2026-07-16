//! Example/edge-case tests for the daemon lifecycle: session
//! start/stop, failure cleanup, workspace-bootstrap polling, listing,
//! and boot-time reconcile of persisted sessions.
use super::test_support::*;
use super::*;
use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
use crate::audit::{NixCacheAuditDecision, NixCacheAuditEntry, NixCacheAuditRoute};
use crate::core::RequestId;
use crate::vm_git::{DEFAULT_WORKSPACE_BRANCH, WorkspaceWarmMode};
use proptest::prelude::*;
use std::fs;
use std::path::Path;

#[tokio::test]
async fn vm_broker_placement_requires_an_agent_kind() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) =
        daemon_config_with_broker_placement(dir.path(), &fake_tool, BrokerPlacement::Vm);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state_with_audit(AuditLog::open(dir.path().join("audit.db")).unwrap());

    // No agent_kind: the broker has no GitHub App to mint with, so vm placement
    // fails fast — before any container/network work.
    let err = daemon
        .start_session(
            Arc::clone(&state),
            Some("vm placement".into()),
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap_err();
    let AgentVmDaemonError::StartFailed { source, .. } = err else {
        panic!("vm placement should fail with StartFailed, got {err:?}");
    };
    assert!(
        matches!(*source, AgentVmDaemonError::AgentKindRequiredForVmBroker),
        "expected AgentKindRequiredForVmBroker, got {source:?}"
    );
    assert!(
        !args_log.exists(),
        "no container command should run when agent_kind is missing"
    );
}

#[tokio::test]
async fn vm_broker_placement_rejects_agent_run_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) =
        daemon_config_with_broker_placement(dir.path(), &fake_tool, BrokerPlacement::Vm);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state_with_audit(AuditLog::open(dir.path().join("audit.db")).unwrap());

    // The v1 broker VM has no agent-run route, so an agent-run session must be
    // rejected before any container work (rather than start a VM whose guest 404s
    // fetching its run config and strands RunAgent waiting for an outcome).
    let err = daemon
        .start_agent_run_session(
            Arc::clone(&state),
            Some("run".into()),
            AgentKind::Claude,
            "claude-test".into(),
            AgentVmWorkspaceBootstrap {
                repo: "owner/repo".parse().unwrap(),
                destination: None,
                warm: WorkspaceWarmMode::None,
            },
            crate::agent_run::AgentPrompt::new("do it"),
            None,
        )
        .await
        .unwrap_err();
    let AgentVmDaemonError::StartFailed { source, .. } = err else {
        panic!("expected StartFailed, got {err:?}");
    };
    assert!(
        matches!(*source, AgentVmDaemonError::AgentRunUnsupportedForVmBroker),
        "expected AgentRunUnsupportedForVmBroker, got {source:?}"
    );
    assert!(
        !args_log.exists(),
        "no container command should run for a rejected agent-run session"
    );
}

/// A host config the broker VM's materializer accepts: a claude app whose private
/// key secret matches `make_state`'s app config (`gh-app-pk`), no proxy (so the
/// only secret the broker needs is that key), and the vm_http section
/// `broker_config_json` requires.
fn vm_broker_host_config_json() -> String {
    r#"{
        "github_apps": { "claude": { "app_id": 42, "installation_id": 999,
            "installation_owner": "o", "private_key_secret": "gh-app-pk" } },
        "policy": { "default_ttl": 3600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "audit_db": "/tmp/audit.db",
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252, "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0", "broker_port_min": 1024, "broker_port_max": 65535,
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/var/lib/writ/git-work",
                "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864
            }
        }
    }"#
    .to_string()
}

/// A stateful fake `container` for the full vm-broker start: it answers `network
/// inspect` (agent subnet), publishes the broker VM's ready file from its
/// `/writ/session` mount on `run`, returns the broker VM's IP from `inspect`, logs
/// the agent VM's `--env-file`, and answers the bootstrap `exec` probe.
fn write_vm_broker_fake_tool(dir: &Path, args_log: &Path, env_log: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("fake-vm-broker");
    // The real broker publishes a versioned ready doc; the host gates its protocol
    // version and bound port (see `broker_vm_runner::gate_ready_doc`). The fake
    // must therefore publish a *well-formed* doc for the fixed test port (1024,
    // the low end of the config's broker port range), not an empty marker.
    let ready_json = serde_json::to_string(&crate::broker_protocol::BrokerReadyDoc {
        protocol_version: crate::broker_protocol::BROKER_PROTOCOL_VERSION,
        broker_port: 1024,
        writd_build: None,
    })
    .unwrap();
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> {args_log}\n\
         if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then\n\
         printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'; exit 0; fi\n\
         if [ \"$1\" = inspect ]; then id=\"${{2#writ-broker-vm-}}\";\n\
         printf '[{{\"status\":{{\"networks\":[{{\"network\":\"writ-agent-net-%s\",\"ipv4Address\":\"192.168.252.7/24\"}}],\"state\":\"running\"}}}}]\\n' \"$id\"; exit 0; fi\n\
         if [ \"$1\" = run ]; then prev=\"\";\n\
         for a in \"$@\"; do\n\
         case \"$a\" in type=virtiofs,source=*,target=/writ/session*) s=\"${{a#type=virtiofs,source=}}\"; s=\"${{s%%,*}}\"; printf '%s' '{ready_json}' > \"$s/ready\" ;; esac\n\
         if [ \"$prev\" = --env-file ]; then printf '%s\\n' \"$a\" > {env_path}; cat \"$a\" > {env_log}; fi\n\
         prev=\"$a\"\n\
         done\n\
         exit 0; fi\n\
         if [ \"$1\" = exec ]; then case \"${{5:-}}\" in *bootstrap-failed*) printf 'ok' ;; esac; fi\n\
         exit 0\n",
        args_log = shell_quote(args_log),
        env_log = shell_quote(env_log),
        env_path = shell_quote(&dir.join("env-path.log")),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[tokio::test]
async fn vm_broker_placement_starts_agent_pointed_at_the_broker_vm() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_vm_broker_fake_tool(dir.path(), &args_log, &env_log);
    let (config, _state_store) =
        daemon_config_with_broker_placement(dir.path(), &fake_tool, BrokerPlacement::Vm);
    // The broker VM read-write-mounts the audit DB's directory, which must be
    // dedicated (see `ensure_audit_dir_is_dedicated`), so give it its own subdir
    // rather than sharing `dir` with the test fixtures.
    let audit_db = dir.path().join("audit").join("audit.db");
    std::fs::create_dir_all(audit_db.parent().unwrap()).unwrap();
    // Thread the host facts the vm arm needs (raw config + effective audit DB),
    // exactly as writd does.
    let config = config.with_broker_vm_host_facts(&vm_broker_host_config_json(), &audit_db);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state_with_audit(AuditLog::open(&audit_db).unwrap());
    // The host secret store holds the claude app key the broker exports.
    state
        .secrets
        .put(&crate::secret::SecretKey::new("gh-app-pk").unwrap(), "PEM")
        .unwrap();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            Some("vm session".into()),
            Some(AgentKind::Claude),
            Some("claude-test".into()),
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();

    // The agent is pointed at the broker VM's discovered IP on the fixed port.
    assert_eq!(started.broker_url(), "http://192.168.252.7:1024/");
    let env = fs::read_to_string(&env_log).unwrap();
    assert!(
        env.contains(&format!(
            "{AGENT_VM_BROKER_URL_ENV}=http://192.168.252.7:1024/"
        )),
        "agent env must point WRIT_BROKER_URL at the broker VM: {env}"
    );
    assert!(env.contains(&format!("{AGENT_VM_BROKER_TOKEN_ENV}=writ-vm-")));
    assert!(
        !env.contains(AGENT_VM_NIX_PREWARM_URL_ENV),
        "no pre-warm dir is configured, so the strict warm substituter must not be advertised even under vm placement: {env}"
    );
    let args = fs::read_to_string(&args_log).unwrap();
    // The broker VM was launched, and the host PF allow target is the broker VM IP.
    assert!(
        args.lines().any(|l| l.contains("writ-broker-vm-")),
        "broker VM must be launched: {args}"
    );
    assert!(
        args.contains("--broker-host 192.168.252.7"),
        "host PF must target the broker VM IP: {args}"
    );

    // list_sessions reports the discovered broker VM URL (not the subnet gateway)
    // and the session as runtime-attached (not orphaned), even though the vm arm
    // keeps no in-process broker.
    let sessions = daemon.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].broker_urls.as_slice(),
        &["http://192.168.252.7:1024/".to_string()],
        "running vm session must list the broker VM URL"
    );
    assert!(
        sessions[0].runtime_attached,
        "a live vm-broker session must be reported attached, not orphaned"
    );

    // The start materialised broker session material (config, spec, bearer, copied
    // secrets) under <state_dir>/broker-vm/<session_id>/.
    let material = dir
        .path()
        .join("state")
        .join("broker-vm")
        .join(started.session_id().to_string());
    assert!(material.exists(), "broker material must exist after start");

    // Stop the vm session: it must succeed (the broker teardown is absence-based,
    // so the fake reporting everything gone does not strand it) and remove the
    // per-session material — copied secrets included.
    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
    assert!(
        !material.exists(),
        "stop must remove the broker material (copied secrets included)"
    );
}

#[tokio::test]
async fn vm_broker_placement_advertises_prewarm_substituter_when_prewarm_dir_configured() {
    // Parity with host placement: once the vm broker serves the pre-warmed closure
    // (re-pointed dir + read-only mount), the agent's strict devShell warm must be
    // pinned to /v1/nix/prewarm just as it is for host placement.
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_vm_broker_fake_tool(dir.path(), &args_log, &env_log);
    let prewarm_dir = dir.path().join("prewarm-cache");
    let (config, _state_store) = daemon_config_with_prewarm_dir_and_placement(
        dir.path(),
        &fake_tool,
        &prewarm_dir,
        BrokerPlacement::Vm,
    );
    // Dedicated audit dir: the broker VM mounts it read-write (see
    // `ensure_audit_dir_is_dedicated`).
    let audit_db = dir.path().join("audit").join("audit.db");
    std::fs::create_dir_all(audit_db.parent().unwrap()).unwrap();
    let config = config.with_broker_vm_host_facts(&vm_broker_host_config_json(), &audit_db);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state_with_audit(AuditLog::open(&audit_db).unwrap());
    state
        .secrets
        .put(&crate::secret::SecretKey::new("gh-app-pk").unwrap(), "PEM")
        .unwrap();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            Some("vm session".into()),
            Some(AgentKind::Claude),
            Some("claude-test".into()),
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();

    let env = fs::read_to_string(&env_log).unwrap();
    assert!(
        env.contains(&format!(
            "{AGENT_VM_NIX_PREWARM_URL_ENV}={}",
            nix_prewarm_url_for_broker_url(started.broker_url())
        )),
        "vm placement with a configured pre-warm dir must advertise the strict substituter: {env}"
    );

    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
}

#[tokio::test]
async fn daemon_start_injects_vm_http_env_without_persisting_token_and_stop_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            Some("agent vm".into()),
            Some(AgentKind::Codex),
            Some("gpt-test".into()),
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();

    assert!(started.broker_url().starts_with("http://192.168.252.1:"));
    let audit_session = state
        .audit
        .get_session(started.session_id())
        .unwrap()
        .unwrap();
    assert_eq!(audit_session.label.as_deref(), Some("agent vm"));
    assert_eq!(audit_session.agent_kind, Some(AgentKind::Codex));
    assert!(audit_session.closed_at.is_none());

    let env = fs::read_to_string(&env_log).unwrap();
    assert!(env.contains(&format!(
        "{AGENT_VM_BROKER_URL_ENV}={}",
        started.broker_url()
    )));
    assert!(env.contains(&format!("{AGENT_VM_BROKER_TOKEN_ENV}=writ-vm-")));
    assert!(env.contains(&format!(
        "{AGENT_VM_NIX_CACHE_URL_ENV}={}",
        nix_cache_url_for_broker_url(started.broker_url())
    )));
    assert!(env.contains(&format!(
        "{AGENT_VM_NIX_BASIC_LOGIN_ENV}={VM_NIX_BASIC_LOGIN}"
    )));
    assert!(env.contains(&format!(
        "{AGENT_VM_NIX_NETRC_ENV}={AGENT_VM_NIX_NETRC_PATH}"
    )));
    assert!(env.contains(&format!(
        "{AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV}={TEST_NIX_CACHE_PUBLIC_KEY}"
    )));
    assert!(env.contains(&format!(
        "{AGENT_VM_NIX_CONF_DIR_ENV}={AGENT_VM_NIX_CONF_DIR}"
    )));
    assert!(
        !env.contains(AGENT_VM_NIX_PREWARM_URL_ENV),
        "no pre-warm dir is configured, so the strict warm substituter must not be advertised: {env}"
    );
    let args = fs::read_to_string(&args_log).unwrap();
    assert!(args.contains("--env-file"));
    assert!(args.contains("writ-agent-vm-nix-setup"));
    assert!(!args.contains("writ-vm-"), "{args}");
    let state_json = fs::read_to_string(
        dir.path()
            .join("state")
            .join(format!("{}.json", started.session_id())),
    )
    .unwrap();
    assert!(!state_json.contains("writ-vm-"), "{state_json}");
    let env_path = fs::read_to_string(&env_path_log).unwrap();
    assert!(
        !Path::new(env_path.trim()).exists(),
        "guest env file should be removed after container run"
    );

    let sessions = daemon.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, started.session_id());
    assert_eq!(sessions[0].status, AgentVmSessionStateStatus::Running);
    assert_eq!(sessions[0].subnet_index, 252);
    assert_eq!(
        sessions[0].vm_name.as_str(),
        format!("writ-agent-vm-{}", started.session_id())
    );
    assert_eq!(
        sessions[0].network_name.as_str(),
        format!("writ-agent-net-{}", started.session_id())
    );
    assert_eq!(
        sessions[0].broker_urls.as_slice(),
        &[started.broker_url().to_string()]
    );
    assert!(sessions[0].runtime_attached);

    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
    assert!(state_store.load(started.session_id()).is_err());
    let audit_session = state
        .audit
        .get_session(started.session_id())
        .unwrap()
        .unwrap();
    assert!(audit_session.closed_at.is_some());
}

#[tokio::test]
async fn daemon_stop_removes_the_broker_material_dir() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            None,
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();

    // Simulate this session's broker material (the start arm writes it here for
    // vm placement). Stop removes the per-session dir on a successful teardown —
    // unconditional, so it also collects any copied secrets. Exercised here via
    // the host start/stop flow, which can actually start.
    let material = dir
        .path()
        .join("state")
        .join("broker-vm")
        .join(started.session_id().to_string());
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("bearer-token"), b"writ-vm-secret").unwrap();

    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
    assert!(
        !material.exists(),
        "stop must remove the broker material dir (copied secrets included)"
    );
}

#[tokio::test]
async fn daemon_stop_preserves_state_record_when_material_removal_fails() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            None,
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();
    let session_id = started.session_id();

    // Wedge the material removal: put a *file* where the per-session material dir
    // would be, so `remove_dir_all` fails with NotADirectory (ENOTDIR) rather than
    // succeeding or being a NotFound no-op. Removing copied secrets must be a hard
    // step: a failure keeps the persisted state record — the sole reconciliation
    // obligation — so the stranded secrets are retried, not forgotten.
    let broker_vm_root = dir.path().join("state").join("broker-vm");
    fs::create_dir_all(&broker_vm_root).unwrap();
    let material = broker_vm_root.join(session_id.to_string());
    fs::write(&material, b"copied-secret").unwrap();

    let err = daemon.stop_session(&state, session_id).await.unwrap_err();
    assert!(
        matches!(err, AgentVmDaemonError::BrokerMaterialRemove(_)),
        "a material-removal failure must be surfaced, got {err:?}"
    );

    // The state record survives, so a boot-time reconcile (or a later stop) still
    // sees the session and can retry. The session is no longer runtime-attached
    // (the broker is torn down); the audit row was closed before the material step.
    let remaining = state_store.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id(), session_id);
    assert!(
        !daemon.list_sessions().await.unwrap()[0].runtime_attached,
        "a torn-down session must not report as runtime-attached"
    );
    assert!(
        state
            .audit
            .get_session(session_id)
            .unwrap()
            .unwrap()
            .closed_at
            .is_some()
    );

    // Clear the obstruction; the retained obligation now drives to completion:
    // the copied secrets go and the state record is dropped.
    fs::remove_file(&material).unwrap();
    daemon.stop_session(&state, session_id).await.unwrap();
    assert!(!material.exists());
    assert!(state_store.load_all().unwrap().is_empty());
}

#[tokio::test]
async fn daemon_start_advertises_prewarm_substituter_when_prewarm_dir_configured() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let prewarm_dir = dir.path().join("prewarm-cache");
    let (config, _state_store) =
        daemon_config_with_prewarm_dir(dir.path(), &fake_tool, &prewarm_dir);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            None,
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();

    let env = fs::read_to_string(&env_log).unwrap();
    assert!(
        env.contains(&format!(
            "{AGENT_VM_NIX_PREWARM_URL_ENV}={}",
            nix_prewarm_url_for_broker_url(started.broker_url())
        )),
        "a configured pre-warm dir must advertise the strict substituter: {env}"
    );

    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
}

#[tokio::test]
async fn daemon_stop_does_not_close_audit_session_when_vm_state_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();
    let session_id = SessionId::new();
    state
        .audit
        .open_session(&SessionRecord {
            session_id,
            label: Some("ordinary broker session".into()),
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::now(),
            closed_at: None,
        })
        .unwrap();

    let err = daemon.stop_session(&state, session_id).await.unwrap_err();

    assert!(matches!(
        err,
        AgentVmDaemonError::Manager(AgentVmSessionManagerError::State(
            AgentVmSessionStateError::NotFound { .. }
        ))
    ));
    let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
    assert!(audit_session.closed_at.is_none());
}

#[tokio::test]
async fn daemon_start_failure_after_audit_open_closes_audit_session() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    occupy_subnet(&state_store, 253);
    let daemon = AgentVmDaemon::new(config);
    let audit_db = dir.path().join("audit.db");
    let state = make_state_with_audit(AuditLog::open(&audit_db).unwrap());

    let err = daemon
        .start_session(
            Arc::clone(&state),
            Some("subnet pool exhausted".into()),
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        AgentVmDaemonError::StartFailed {
            session_id: _,
            source
        } if matches!(*source, AgentVmDaemonError::NoAvailableSubnet { min: 252, max: 253 })
    ));
    let conn = rusqlite::Connection::open(audit_db).unwrap();
    let (rows, closed): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN closed_at IS NOT NULL THEN 1 ELSE 0 END), 0) \
                 FROM session WHERE label = 'subnet pool exhausted'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((rows, closed), (1, 1));
}

#[tokio::test]
async fn daemon_start_failure_after_vm_http_prepare_does_not_register_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let fake_tool = write_fake_network_create_failure_tool(dir.path(), &args_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let err = daemon
        .start_session(
            Arc::clone(&state),
            Some("container network create fails".into()),
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap_err();

    let session_id = match err {
        AgentVmDaemonError::StartFailed { session_id, source } => {
            assert!(matches!(*source, AgentVmDaemonError::Manager(_)));
            session_id
        }
        other => panic!("unexpected start error: {other:?}"),
    };
    assert!(daemon.running.lock().await.is_empty());
    assert!(state_store.load(session_id).is_err());
    let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
    assert!(audit_session.closed_at.is_some());
}

#[tokio::test]
async fn daemon_workspace_bootstrap_success_records_audit_intent() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool =
        write_fake_workspace_success_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _) = daemon_config(dir.path(), &fake_tool);
    let state = make_state();
    let daemon = AgentVmDaemon::new(config);
    let workspace = AgentVmWorkspaceBootstrap {
        repo: "owner/repo".parse().unwrap(),
        destination: None,
        warm: WorkspaceWarmMode::Sources,
    };

    let started = daemon
        .start_session(
            Arc::clone(&state),
            Some("workspace bootstrap success".into()),
            None,
            None,
            Some(workspace),
            vec!["codex".into()],
        )
        .await
        .unwrap();

    let audit_record = state
        .audit
        .get_agent_vm_workspace_bootstrap(started.session_id())
        .unwrap()
        .unwrap();
    assert_eq!(audit_record.repo, "owner/repo");
    assert_eq!(audit_record.destination, "/workspace/repo");
    assert_eq!(audit_record.branch, DEFAULT_WORKSPACE_BRANCH);
    assert_eq!(audit_record.warm, "sources");

    daemon
        .stop_session(&state, started.session_id())
        .await
        .unwrap();
}

#[tokio::test]
async fn daemon_workspace_bootstrap_failure_removes_state_and_closes_audit_session() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool =
        write_fake_workspace_failure_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    let state = make_state();
    let daemon = AgentVmDaemon::new(config);
    let workspace = AgentVmWorkspaceBootstrap {
        repo: "owner/repo".parse().unwrap(),
        destination: Some(PathBuf::from("/workspace/repo")),
        warm: WorkspaceWarmMode::None,
    };

    let err = daemon
        .start_session(
            Arc::clone(&state),
            Some("workspace bootstrap failure".into()),
            None,
            None,
            Some(workspace),
            vec!["codex".into()],
        )
        .await
        .unwrap_err();

    let session_id = match err {
        AgentVmDaemonError::StartFailed { session_id, source } => {
            assert!(matches!(
                *source,
                AgentVmDaemonError::WorkspaceBootstrapFailed { .. }
            ));
            session_id
        }
        other => panic!("unexpected workspace bootstrap error: {other:?}"),
    };
    assert!(state_store.load_all().unwrap().is_empty());
    assert!(daemon.running.lock().await.is_empty());
    let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
    assert_eq!(
        audit_session.label.as_deref(),
        Some("workspace bootstrap failure")
    );
    assert!(audit_session.closed_at.is_some());
    let audit_record = state
        .audit
        .get_agent_vm_workspace_bootstrap(session_id)
        .unwrap()
        .unwrap();
    assert_eq!(audit_record.repo, "owner/repo");
    assert_eq!(audit_record.destination, "/workspace/repo");
    assert_eq!(audit_record.warm, "none");
}

#[tokio::test]
async fn daemon_list_reports_persisted_session_without_runtime_as_detached() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let state = state_store.load_all().unwrap().pop().unwrap();
    let daemon = AgentVmDaemon::new(config);

    let sessions = daemon.list_sessions().await.unwrap();

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, state.session_id());
    assert_eq!(sessions[0].status, AgentVmSessionStateStatus::Starting);
    assert_eq!(sessions[0].subnet_index, state.subnet_index());
    assert_eq!(sessions[0].vm_name.as_str(), state.names().vm());
    assert_eq!(sessions[0].network_name.as_str(), state.names().network());
    assert_eq!(
        sessions[0].broker_urls.as_slice(),
        &["http://192.168.252.1:51375/".to_string()]
    );
    assert!(!sessions[0].runtime_attached);
}

/// A vm-broker session whose stop/cleanup failed re-attaches its log tail, so it
/// stays reported as runtime-attached (observable + retryable) rather than
/// appearing orphaned. `false` (no prior forwarder) must not attach anything.
#[tokio::test]
async fn reattach_broker_log_forwarder_marks_session_attached() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let state = state_store.load_all().unwrap().pop().unwrap();
    let session_id = state.session_id();
    let daemon = AgentVmDaemon::new(config);

    // No prior forwarder: nothing is attached (mirrors the detached case).
    daemon
        .reattach_broker_log_forwarder_if(false, session_id)
        .await;
    assert!(!daemon.list_sessions().await.unwrap()[0].runtime_attached);

    // A failed stop that had a forwarder re-attaches it: the session is now
    // reported attached again.
    daemon
        .reattach_broker_log_forwarder_if(true, session_id)
        .await;
    assert!(
        daemon.list_sessions().await.unwrap()[0].runtime_attached,
        "re-attached vm-broker session must be reported attached, not orphaned"
    );
}

#[tokio::test]
async fn daemon_reconcile_on_empty_store_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    assert!(report.cleaned().is_empty());
    assert!(report.failed().is_empty());
    assert!(report.is_clean());
}

#[tokio::test]
async fn daemon_reconcile_cleans_persisted_state_and_closes_audit() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let session_id = state_store.load_all().unwrap().pop().unwrap().session_id();
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    audit
        .open_session(&SessionRecord {
            session_id,
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .unwrap();
    let daemon = AgentVmDaemon::new(config);

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    assert_eq!(report.cleaned(), &[session_id]);
    assert!(report.failed().is_empty());
    assert!(state_store.load_all().unwrap().is_empty());
    let recorded = audit.get_session(session_id).unwrap().unwrap();
    assert!(recorded.closed_at.is_some());
}

#[tokio::test]
async fn daemon_reconcile_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    let daemon = AgentVmDaemon::new(config);

    let first = daemon.reconcile_persisted_sessions(&audit).await.unwrap();
    assert_eq!(first.cleaned().len(), 1);
    assert!(first.failed().is_empty());

    let second = daemon.reconcile_persisted_sessions(&audit).await.unwrap();
    assert!(second.cleaned().is_empty());
    assert!(second.failed().is_empty());
}

#[tokio::test]
async fn daemon_reconcile_handles_multiple_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    occupy_subnet(&state_store, 253);
    let mut expected: Vec<SessionId> = state_store
        .load_all()
        .unwrap()
        .into_iter()
        .map(|state| state.session_id())
        .collect();
    expected.sort();
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    let daemon = AgentVmDaemon::new(config);

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    let mut cleaned: Vec<SessionId> = report.cleaned().to_vec();
    cleaned.sort();
    assert_eq!(cleaned, expected);
    assert!(report.failed().is_empty());
    assert!(state_store.load_all().unwrap().is_empty());
}

#[tokio::test]
async fn daemon_reconcile_preserves_state_record_when_cleanup_fails() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let fake_tool = write_fake_pf_remove_failure_tool(dir.path(), &args_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let session_id = state_store.load_all().unwrap().pop().unwrap().session_id();
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    audit
        .open_session(&SessionRecord {
            session_id,
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .unwrap();
    let daemon = AgentVmDaemon::new(config);

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    assert!(report.cleaned().is_empty());
    assert_eq!(report.failed().len(), 1);
    let failure = &report.failed()[0];
    assert_eq!(failure.session_id(), session_id);
    assert_eq!(failure.stage(), AgentVmReconcileStage::Cleanup);
    let remaining = state_store.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id(), session_id);
    // Broker authority is revoked independently of infrastructure teardown: the
    // audit row is closed before teardown, so a broker (VM) that outlived the
    // previous daemon cannot keep minting while this failed cleanup is retried.
    let recorded = audit.get_session(session_id).unwrap().unwrap();
    assert!(recorded.closed_at.is_some());
}

/// Boot reconcile of a session whose agent VM cannot be proven absent (its
/// removals never take): the PF anchor — the sole isolation of a possibly-live
/// guest from host services — MUST be preserved, and broker authority MUST be
/// revoked regardless of the failed teardown.
#[tokio::test]
async fn daemon_reconcile_preserves_firewall_and_revokes_authority_when_vm_absence_unproven() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let present_file = dir.path().join("present-vms");
    let fake_tool = write_fake_vm_present_tool(dir.path(), &args_log, &present_file);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let session_id = state_store.load_all().unwrap().pop().unwrap().session_id();
    // Make the agent VM probe as still-present for this session: `container list`
    // keeps reporting it and the removals never clear the file, so VM cleanup
    // cannot prove absence.
    fs::write(&present_file, format!("writ-agent-vm-{session_id}\n")).unwrap();
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    audit
        .open_session(&SessionRecord {
            session_id,
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .unwrap();
    let daemon = AgentVmDaemon::new(config);

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    assert!(report.cleaned().is_empty());
    assert_eq!(report.failed().len(), 1);
    assert_eq!(report.failed()[0].stage(), AgentVmReconcileStage::Cleanup);

    // Problem A — the PF anchor (and the shared network) MUST NOT be removed while
    // the agent VM cannot be proven absent.
    let args = fs::read_to_string(&args_log).unwrap();
    assert!(
        !args
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some("remove")),
        "the PF anchor must be preserved until the VM is proven absent; args:\n{args}"
    );
    assert!(
        !args.contains("network rm") && !args.contains("network delete"),
        "the shared network must not be removed under a possibly-live VM; args:\n{args}"
    );

    // Problem B — broker authority is revoked independently of teardown.
    assert!(
        audit
            .get_session(session_id)
            .unwrap()
            .unwrap()
            .closed_at
            .is_some()
    );

    // The state record is kept so the next boot retries the teardown.
    let remaining = state_store.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id(), session_id);
}

/// A stop whose infrastructure teardown fails (the `pf-helper remove` step exits
/// non-zero) must still revoke broker authority: close the audit session and shut
/// down the in-process broker, leaving a possibly-live guest de-authorised rather
/// than authorised, while keeping the state record for retry.
#[tokio::test]
async fn daemon_stop_revokes_authority_when_teardown_fails() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_stop_firewall_remove_failure_tool(
        dir.path(),
        &args_log,
        &env_path_log,
        &env_log,
    );
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state();

    let started = daemon
        .start_session(
            Arc::clone(&state),
            None,
            None,
            None,
            None,
            vec!["sleep".into(), "600".into()],
        )
        .await
        .unwrap();
    let session_id = started.session_id();

    let err = daemon.stop_session(&state, session_id).await.unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmDaemonError::Manager(AgentVmSessionManagerError::Stop(_))
        ),
        "a firewall-removal failure surfaces as a Stop cleanup error, got {err:?}"
    );

    // Authority is revoked even though teardown failed: audit session closed and
    // the in-process broker shut down and dropped.
    assert!(
        state
            .audit
            .get_session(session_id)
            .unwrap()
            .unwrap()
            .closed_at
            .is_some()
    );
    assert!(
        daemon.running.lock().await.is_empty(),
        "the in-process broker must be shut down even when teardown fails"
    );
    assert!(
        !daemon.list_sessions().await.unwrap()[0].runtime_attached,
        "a de-authorised session must not report as runtime-attached"
    );

    // The state record is kept so a later stop / boot reconcile retries teardown.
    let remaining = state_store.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id(), session_id);
}

#[tokio::test]
async fn daemon_reconcile_preserves_state_record_when_material_removal_fails() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, state_store) = daemon_config(dir.path(), &fake_tool);
    occupy_subnet(&state_store, 252);
    let session_id = state_store.load_all().unwrap().pop().unwrap().session_id();
    let audit = Arc::new(AuditLog::open_in_memory().unwrap());
    audit
        .open_session(&SessionRecord {
            session_id,
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .unwrap();
    let daemon = AgentVmDaemon::new(config);

    // Wedge the material removal (see the stop-path test): a file where the
    // per-session material dir would be forces `remove_dir_all` to fail. Teardown
    // succeeds, so reconcile reaches — and fails at — the MaterialRemove stage.
    let broker_vm_root = dir.path().join("state").join("broker-vm");
    fs::create_dir_all(&broker_vm_root).unwrap();
    let material = broker_vm_root.join(session_id.to_string());
    fs::write(&material, b"copied-secret").unwrap();

    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();

    assert!(report.cleaned().is_empty());
    assert_eq!(report.failed().len(), 1);
    let failure = &report.failed()[0];
    assert_eq!(failure.session_id(), session_id);
    assert_eq!(failure.stage(), AgentVmReconcileStage::MaterialRemove);
    // The state record is kept for the next boot's retry rather than being
    // dropped with the copied secrets stranded on disk. The audit row was closed
    // (MaterialRemove is ordered after AuditClose).
    let remaining = state_store.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id(), session_id);
    assert!(
        audit
            .get_session(session_id)
            .unwrap()
            .unwrap()
            .closed_at
            .is_some()
    );

    // Clear the obstruction; the retained obligation reconciles cleanly next time.
    fs::remove_file(&material).unwrap();
    let report = daemon.reconcile_persisted_sessions(&audit).await.unwrap();
    assert_eq!(report.cleaned(), &[session_id]);
    assert!(report.failed().is_empty());
    assert!(state_store.load_all().unwrap().is_empty());
}

#[test]
fn nix_cache_url_is_the_broker_url_under_the_cache_route() {
    assert_eq!(
        nix_cache_url_for_broker_url("http://192.168.252.1:51375/"),
        "http://192.168.252.1:51375/v1/nix/cache"
    );
    assert_eq!(
        nix_cache_url_for_broker_url("http://192.168.252.1:51375"),
        "http://192.168.252.1:51375/v1/nix/cache"
    );
}

#[test]
fn nix_prewarm_url_is_the_broker_url_under_the_prewarm_route() {
    assert_eq!(
        nix_prewarm_url_for_broker_url("http://192.168.252.1:51375/"),
        "http://192.168.252.1:51375/v1/nix/prewarm"
    );
    assert_eq!(
        nix_prewarm_url_for_broker_url("http://192.168.252.1:51375"),
        "http://192.168.252.1:51375/v1/nix/prewarm"
    );
}

fn nix_cache_entry(target: &str, route: NixCacheAuditRoute, status: u16) -> NixCacheAuditEntry {
    let session_id = SessionId::new();
    NixCacheAuditEntry {
        request_id: RequestId::new(),
        session_id,
        received_at: UnixMillis::from_millis(1),
        method: "GET".into(),
        target: target.into(),
        route,
        decision: NixCacheAuditDecision::Allow,
        completed_at: Some(UnixMillis::from_millis(2)),
        http_status: Some(status),
        upstream_url: None,
        upstream_status: None,
        response_bytes: Some(9),
        error: None,
    }
}

#[test]
fn workspace_bootstrap_prewarm_diagnostic_summarises_strict_misses() {
    let entries = vec![
        nix_cache_entry(
            "/v1/nix/prewarm/00000000000000000000000000000000.narinfo",
            NixCacheAuditRoute::NarInfo,
            404,
        ),
        nix_cache_entry(
            "/v1/nix/prewarm/11111111111111111111111111111111.narinfo",
            NixCacheAuditRoute::NarInfo,
            404,
        ),
        nix_cache_entry(
            "/v1/nix/prewarm/22222222222222222222222222222222.narinfo",
            NixCacheAuditRoute::NarInfo,
            200,
        ),
        nix_cache_entry(
            "/v1/nix/prewarm/nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz",
            NixCacheAuditRoute::Nar,
            200,
        ),
        nix_cache_entry(
            "/v1/nix/prewarm/nar/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.nar.xz",
            NixCacheAuditRoute::Nar,
            404,
        ),
        nix_cache_entry(
            "/v1/nix/cache/33333333333333333333333333333333.narinfo",
            NixCacheAuditRoute::NarInfo,
            404,
        ),
    ];

    let diagnostic = workspace_bootstrap_prewarm_diagnostic(&entries).unwrap();

    assert!(diagnostic.contains("narinfo: 2 missing, 1 served"));
    assert!(diagnostic.contains("nar: 1 missing, 1 served"));
    assert!(diagnostic.contains(
        "first missing narinfo hashes: 00000000000000000000000000000000, \
         11111111111111111111111111111111"
    ));
    assert!(diagnostic.contains("--warm sources"));
    assert!(diagnostic.contains("--warm none"));
    assert!(!diagnostic.contains("33333333333333333333333333333333"));
}

#[test]
fn workspace_bootstrap_prewarm_diagnostic_is_absent_without_prewarm_misses() {
    let entries = vec![
        nix_cache_entry(
            "/v1/nix/prewarm/00000000000000000000000000000000.narinfo",
            NixCacheAuditRoute::NarInfo,
            200,
        ),
        nix_cache_entry(
            "/v1/nix/prewarmevil/11111111111111111111111111111111.narinfo",
            NixCacheAuditRoute::NarInfo,
            404,
        ),
        nix_cache_entry(
            "/v1/nix/cache/22222222222222222222222222222222.narinfo",
            NixCacheAuditRoute::NarInfo,
            404,
        ),
    ];

    assert_eq!(workspace_bootstrap_prewarm_diagnostic(&entries), None);
}

#[test]
fn workspace_bootstrap_poll_interval_backs_off_after_initial_polls() {
    assert_eq!(
        workspace_bootstrap_poll_interval(0),
        AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
    );
    assert_eq!(
        workspace_bootstrap_poll_interval(AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS - 1),
        AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
    );
    assert_eq!(
        workspace_bootstrap_poll_interval(AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS),
        AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL
    );
}

#[test]
fn workspace_bootstrap_failure_message_is_bounded_and_control_scrubbed() {
    let raw = format!(
        "\u{1b}[31m{}\u{7}",
        "x".repeat(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT + 32)
    );

    let message = normalise_workspace_bootstrap_failure_message(&raw);

    assert!(
        message.len()
            <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT
                + AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER.len()
    );
    // The trailing BEL falls inside the kept tail, so it must be scrubbed.
    assert!(!message.contains('\u{7}'));
    assert!(!message.contains('\u{1b}'));
    // The marker leads, because the meaningful Nix error lives at the tail.
    assert!(message.starts_with(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER));
}

#[test]
fn workspace_bootstrap_failure_message_keeps_tail_not_head() {
    // Nix emits hundreds of `copying path ...` progress lines before the line
    // that actually explains the failure. The head-noise alone overflows the
    // limit, so the meaningful tail must survive while the head is dropped.
    let head_marker = "HEAD_MARKER_SHOULD_BE_DROPPED\n";
    let noise = "copying path '/nix/store/deadbeefdeadbeefdeadbeefdeadbeef-source' from cache...\n"
        .repeat(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT / 16);
    let real_error = "error: cannot build '/nix/store/abcd.drv' since max-jobs is set to 0";
    let raw = format!("{head_marker}{noise}{real_error}");
    assert!(raw.len() > AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT);

    let message = normalise_workspace_bootstrap_failure_message(&raw);

    assert!(message.starts_with(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER));
    assert!(message.ends_with(real_error));
    assert!(!message.contains(head_marker));
}

#[test]
fn workspace_bootstrap_failure_message_passes_short_input_through_with_scrubbing() {
    let raw = "error: oh no\u{1b}[0m\u{7}\twith tab\n";

    let message = normalise_workspace_bootstrap_failure_message(raw);

    // Short enough to keep verbatim: no marker, controls (ESC/BEL) scrubbed,
    // tab and newline preserved.
    assert_eq!(message, "error: oh no?[0m?\twith tab\n");
    assert!(!message.contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER));
}

fn failure_message_input() -> impl Strategy<Value = String> {
    // Repeat an arbitrary (possibly multi-byte, possibly control-laden) unit so
    // the generator straddles the truncation threshold instead of only ever
    // producing short strings.
    (
        prop::collection::vec(any::<char>(), 1..64),
        0usize..400usize,
    )
        .prop_map(|(chars, reps)| chars.into_iter().collect::<String>().repeat(reps))
}

proptest! {
    #[test]
    fn workspace_bootstrap_failure_message_is_bounded_scrubbed_and_tail_preserving(
        raw in failure_message_input(),
    ) {
        let scrubbed: String = raw
            .chars()
            .map(|ch| if ch.is_control() && ch != '\n' && ch != '\t' { '?' } else { ch })
            .collect();

        let message = normalise_workspace_bootstrap_failure_message(&raw);

        // No terminal-corrupting control characters survive.
        prop_assert!(
            !message.chars().any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
        );
        // Always bounded by the limit plus the (prepended) marker.
        prop_assert!(
            message.len()
                <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT
                    + AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER.len()
        );

        if scrubbed.len() <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT {
            // Fits: passed through verbatim with no marker.
            prop_assert_eq!(&message, &scrubbed);
        } else {
            // Overflows: marker leads, and the kept content is a genuine suffix
            // of the scrubbed input (the tail, not the head).
            let content = message
                .strip_prefix(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER)
                .expect("a truncated message must start with the marker");
            prop_assert!(scrubbed.ends_with(content));
            prop_assert!(content.len() <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT);
        }
    }
}
#[tokio::test]
async fn workspace_bootstrap_wait_reports_timeout_at_supplied_bound() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    // A tool that never signals bootstrap-ok/failed, so the wait reaches its
    // timeout (the default tool now reports ok, since every start waits).
    let fake_tool = write_fake_pending_bootstrap_tool(dir.path(), &args_log);
    let (config, _) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);

    let err = daemon
        .release_and_wait_for_workspace_bootstrap_with_timeout("writ-agent-vm-test", Duration::ZERO)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        AgentVmDaemonError::WorkspaceBootstrapTimedOut {
            timeout: Duration::ZERO
        }
    ));
}

#[tokio::test]
async fn workspace_bootstrap_wait_bounds_a_hung_inspect_exec() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    // The inspect exec sleeps far longer than the budget; the release exec
    // still returns fast. A correct wait bounds each exec under the remaining
    // deadline and returns promptly; the pre-fix code checks the deadline only
    // *after* an exec returns, so it would block on the wedged exec.
    let fake_tool = write_fake_hung_inspect_tool(dir.path(), &args_log);
    let (config, _) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);

    // Outer cap well below the guest's 30s sleep: if the per-exec deadline is
    // not enforced, this fires and the `expect` fails loudly rather than
    // hanging the suite.
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        daemon.release_and_wait_for_workspace_bootstrap_with_timeout(
            "writ-agent-vm-test",
            Duration::from_millis(200),
        ),
    )
    .await;

    let err = outcome
        .expect("wait must return within 5s: each guest exec must run under the remaining deadline")
        .unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmDaemonError::WorkspaceBootstrapExecTimedOut { .. }
                | AgentVmDaemonError::WorkspaceBootstrapTimedOut { .. }
        ),
        "expected a timeout error, got {err:?}"
    );
}

#[tokio::test]
async fn workspace_bootstrap_wait_rejects_oversized_inspect_output() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    // The inspect exec floods ~2 MiB of output, past the 1 MiB capture cap. A
    // correct wait caps the read and fails fast; the pre-fix code buffers the
    // whole guest-controlled payload and reports it as a bootstrap failure.
    let fake_tool = write_fake_oversized_inspect_tool(dir.path(), &args_log);
    let (config, _) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);

    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        daemon.release_and_wait_for_workspace_bootstrap_with_timeout(
            "writ-agent-vm-test",
            Duration::from_secs(20),
        ),
    )
    .await;

    let err = outcome
        .expect("wait must return, not buffer the payload unboundedly")
        .unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmDaemonError::WorkspaceBootstrapOutputTooLarge { .. }
        ),
        "expected oversized-output error, got {err:?}"
    );
}

#[tokio::test]
async fn workspace_bootstrap_wait_preserves_tail_of_large_failure() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    // The guest's failure file is large (the actionable error is its last
    // line). A plain `cat` would let the host head-truncate and drop that line
    // as oversized; a cooperative `tail -c` in the inspect script keeps it
    // under the capture cap, so the daemon surfaces it as a normal failure.
    let fake_tool = write_fake_large_failure_tool(dir.path(), &args_log);
    let (config, _) = daemon_config(dir.path(), &fake_tool);
    let daemon = AgentVmDaemon::new(config);

    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        daemon.release_and_wait_for_workspace_bootstrap_with_timeout(
            "writ-agent-vm-test",
            Duration::from_secs(20),
        ),
    )
    .await;

    let err = outcome
        .expect("wait must return")
        .expect_err("a large failure is still a bootstrap failure");
    let AgentVmDaemonError::WorkspaceBootstrapFailed { message } = err else {
        panic!("expected a preserved bootstrap failure, got {err:?}");
    };
    assert!(
        message.contains("NIX_ERROR_SENTINEL"),
        "the actionable tail of a large failure must survive, got: {message:?}"
    );
}
