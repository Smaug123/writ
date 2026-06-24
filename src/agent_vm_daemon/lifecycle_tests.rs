//! Example/edge-case tests for the daemon lifecycle: session
//! start/stop, failure cleanup, workspace-bootstrap polling, listing,
//! and boot-time reconcile of persisted sessions.
use super::test_support::*;
use super::*;
use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
use crate::vm_git::{DEFAULT_WORKSPACE_BRANCH, WorkspaceWarmMode};
use proptest::prelude::*;
use std::fs;
use std::path::Path;

#[tokio::test]
async fn vm_broker_placement_is_rejected_until_implemented() {
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let env_path_log = dir.path().join("env-path.log");
    let env_log = dir.path().join("env.log");
    let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
    let (config, _state_store) =
        daemon_config_with_broker_placement(dir.path(), &fake_tool, BrokerPlacement::Vm);
    let daemon = AgentVmDaemon::new(config);
    let state = make_state_with_audit(AuditLog::open(dir.path().join("audit.db")).unwrap());

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
        matches!(*source, AgentVmDaemonError::BrokerPlacementNotImplemented),
        "vm placement should fail fast with BrokerPlacementNotImplemented, got {source:?}"
    );
    // Fail-fast: the guard runs before any container/network work, so the fake
    // `container` tool was never invoked.
    assert!(
        !args_log.exists(),
        "no container command should run when broker_placement=vm is rejected"
    );
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
    let recorded = audit.get_session(session_id).unwrap().unwrap();
    assert!(recorded.closed_at.is_none());
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
