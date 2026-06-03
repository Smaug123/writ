//! Example/edge-case tests for the guest shell scripts and the
//! guest-command builders. The arbitrary-input framing contract
//! lives in the inline `spec` module beside the code.
use super::guest_command::*;
use super::test_support::*;
use super::*;
use crate::vm_git::WorkspaceWarmMode;
use std::fs;
use std::process::Command;

#[test]
fn guest_nix_setup_script_writes_configured_trusted_public_keys() {
    let dir = tempfile::tempdir().unwrap();
    let netrc = dir.path().join("run").join("netrc");
    let nix_conf_dir = dir.path().join("nix-conf");
    let trusted_public_keys =
        format!("{TEST_NIX_CACHE_PUBLIC_KEY} {SECOND_TEST_NIX_CACHE_PUBLIC_KEY}");

    let status = Command::new("sh")
        .arg("-c")
        .arg(AGENT_VM_GUEST_NIX_SETUP_SCRIPT)
        .arg("writ-agent-vm-nix-setup")
        .arg("true")
        .env("WRIT_BROKER_TOKEN", "writ-vm-token")
        .env(
            "WRIT_NIX_CACHE_URL",
            "http://192.168.252.1:51375/v1/nix/cache",
        )
        .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
        .env("WRIT_NIX_NETRC", &netrc)
        .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, &trusted_public_keys)
        .env("NIX_CONF_DIR", &nix_conf_dir)
        .status()
        .unwrap();

    assert!(status.success());
    let nix_conf = fs::read_to_string(nix_conf_dir.join("nix.conf")).unwrap();
    assert!(nix_conf.contains(&format!("trusted-public-keys = {trusted_public_keys}\n")));
    let netrc = fs::read_to_string(netrc).unwrap();
    assert_eq!(
        netrc,
        "machine 192.168.252.1 login writ-vm password writ-vm-token\n"
    );
}

#[test]
fn non_workspace_nix_setup_does_not_enable_flakes() {
    assert!(AGENT_VM_GUEST_NIX_SETUP_SCRIPT.contains("experimental-features = nix-command"));
    assert!(!AGENT_VM_GUEST_NIX_SETUP_SCRIPT.contains("nix-command flakes"));
    assert!(AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.contains("nix-command flakes"));
}

#[test]
fn agent_run_guest_command_contains_run_id_and_agent_but_not_prompt() {
    let run_id: AgentRunId = "00000000-0000-0000-0000-000000000201".parse().unwrap();
    let prompt = AgentPrompt::new("SECRET prompt");

    let command =
        build_agent_run_guest_command(AgentKind::Claude, run_id, WorkspaceWarmMode::Sources);

    assert_eq!(
        command,
        vec![
            "writ-vm",
            "agent",
            "run",
            "--run-id",
            "00000000-0000-0000-0000-000000000201",
            "--agent",
            "claude",
        ]
    );
    assert!(!format!("{command:?}").contains(prompt.as_str()));
}

#[test]
fn agent_run_devshell_command_wraps_without_adding_prompt() {
    let run_id: AgentRunId = "00000000-0000-0000-0000-000000000202".parse().unwrap();
    let prompt = AgentPrompt::new("SECRET prompt");

    let command =
        build_agent_run_guest_command(AgentKind::Codex, run_id, WorkspaceWarmMode::DevShell);

    assert!(command.starts_with(&[
        "nix".to_string(),
        "--option".to_string(),
        "builders".to_string(),
        "".to_string(),
    ]));
    assert!(command.ends_with(&[
        "writ-vm".to_string(),
        "agent".to_string(),
        "run".to_string(),
        "--run-id".to_string(),
        "00000000-0000-0000-0000-000000000202".to_string(),
        "--agent".to_string(),
        "codex".to_string(),
    ]));
    assert!(!format!("{command:?}").contains(prompt.as_str()));
}

#[test]
fn workspace_bootstrap_script_mentions_sentinel_paths() {
    assert!(
        AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.contains(AGENT_VM_WORKSPACE_BROKER_READY_PATH)
    );
    assert!(
        AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.contains(AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH)
    );
    assert!(
        AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT
            .contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH)
    );
}
#[cfg(unix)]
#[test]
fn workspace_bootstrap_rejects_non_utf8_destination() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let workspace = AgentVmWorkspaceBootstrap {
        repo: "owner/repo".parse().unwrap(),
        destination: Some(PathBuf::from(OsString::from_vec(vec![b'/', 0xff]))),
        warm: WorkspaceWarmMode::None,
    };

    let err =
        wrap_guest_command_with_workspace_bootstrap(&workspace, vec!["true".into()]).unwrap_err();

    assert!(matches!(
        err,
        AgentVmDaemonError::NonUtf8WorkspaceDestination(_)
    ));
}
