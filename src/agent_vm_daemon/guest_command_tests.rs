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
        .arg(nix_conf_prologue_script_for_test())
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
fn guest_nix_conf_disables_build_users_group_for_single_user_root_store() {
    // The guest runs Nix as root in a single-user, root-owned store with no
    // `nixbld` build-users group. Nix defaults `build-users-group` to `nixbld`
    // exactly when euid is 0, so any *local* build (which the `nix develop`
    // warm now permits under `max-jobs = 1`) fails with "the group 'nixbld'
    // ... does not exist". The guest nix.conf must pin `build-users-group =`
    // empty so Nix builds as the calling user (root) rather than switching to
    // a non-existent build user. Asserted on both guest scripts via the shared
    // prologue, so this covers the warm and the agent run alike.
    let dir = tempfile::tempdir().unwrap();
    let netrc = dir.path().join("run").join("netrc");
    let nix_conf_dir = dir.path().join("nix-conf");

    let status = Command::new("sh")
        .arg("-c")
        .arg(nix_conf_prologue_script_for_test())
        .arg("writ-agent-vm-nix-setup")
        .arg("true")
        .env("WRIT_BROKER_TOKEN", "writ-vm-token")
        .env(
            "WRIT_NIX_CACHE_URL",
            "http://192.168.252.1:51375/v1/nix/cache",
        )
        .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
        .env("WRIT_NIX_NETRC", &netrc)
        .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, "")
        .env("NIX_CONF_DIR", &nix_conf_dir)
        .status()
        .unwrap();

    assert!(status.success());
    let nix_conf = fs::read_to_string(nix_conf_dir.join("nix.conf")).unwrap();
    assert!(
        nix_conf.contains("build-users-group =\n"),
        "nix.conf must pin build-users-group empty to build as the calling user; got:\n{nix_conf}"
    );
    assert!(
        !nix_conf.contains("build-users-group = nixbld"),
        "nix.conf must not point build-users-group at the non-existent nixbld group; got:\n{nix_conf}"
    );
}

#[test]
fn non_workspace_nix_setup_does_not_enable_flakes() {
    assert!(nix_setup_script().contains("experimental-features = nix-command"));
    assert!(!nix_setup_script().contains("nix-command flakes"));
    assert!(workspace_bootstrap_script().contains("nix-command flakes"));
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
    let script = workspace_bootstrap_script();
    assert!(script.contains(AGENT_VM_WORKSPACE_BROKER_READY_PATH));
    assert!(script.contains(AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH));
    assert!(script.contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH));
}

#[test]
fn workspace_bootstrap_runs_egress_gate_between_broker_ready_and_workspace_init() {
    let script = workspace_bootstrap_script();

    // The adversarial probe (bash /dev/tcp to public IPv4) and the
    // global-scope IPv6 rejection are present, with a named leak abort.
    assert!(
        script.contains("/dev/tcp/"),
        "gate must probe via bash /dev/tcp"
    );
    assert!(
        script.contains("1.1.1.1:443") && script.contains("8.8.8.8:443"),
        "gate must probe public IPv4 targets"
    );
    assert!(
        script.contains("ip -6 addr show scope global"),
        "gate must reject a global-scope IPv6 address"
    );
    assert!(
        script.contains("LEAK"),
        "gate must name an egress leak on abort"
    );

    // Positioned in the trusted window: after broker-ready (so the positive
    // control is sound) and before any repo/agent code runs.
    let broker_ready = script
        .find(AGENT_VM_WORKSPACE_BROKER_READY_PATH)
        .expect("broker-ready wait present");
    let gate = script.find("1.1.1.1:443").expect("gate present");
    let workspace_init = script
        .find("writ-vm workspace init")
        .expect("workspace init present");
    assert!(
        broker_ready < gate,
        "gate must run after the broker-ready wait"
    );
    assert!(gate < workspace_init, "gate must run before workspace init");
}

#[test]
fn egress_gate_failure_surfaces_through_bootstrap_failed() {
    // A gate failure must report through the same sentinel the daemon already
    // polls, so an egress leak is surfaced rather than silently looping.
    let script = workspace_bootstrap_script();
    let gate = script.find("1.1.1.1:443").expect("gate present");
    let workspace_init = script
        .find("writ-vm workspace init")
        .expect("workspace init present");
    assert!(
        script[gate..workspace_init].contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH),
        "the gate's own failure path must write the bootstrap-failed sentinel"
    );
}

#[test]
fn nix_setup_runs_egress_gate_then_execs_aborting_on_failure() {
    // The non-workspace path gates on egress too: it waits for broker-ready,
    // runs the same gate, and on failure aborts the container (exit) — there is
    // no daemon-polled sentinel here — rather than exec-ing the guest command.
    let script = nix_setup_script();
    assert!(
        script.contains(AGENT_VM_WORKSPACE_BROKER_READY_PATH),
        "nix-setup must wait for broker-ready before the gate"
    );
    assert!(
        script.contains("/dev/tcp/") && script.contains("LEAK"),
        "nix-setup must run the egress gate"
    );
    let gate = script.find("/dev/tcp/").expect("gate present");
    let abort = script.find("exit 1").expect("gate abort present");
    let exec = script.find(r#"exec "$@""#).expect("exec present");
    assert!(
        gate < abort && abort < exec,
        "the gate (and its exit-on-failure) must run before exec-ing the guest command"
    );
}

#[test]
fn both_guest_scripts_share_the_egress_gate() {
    // The broker-ready wait and the gate function are shared, so neither script
    // can silently drift from the other's egress posture.
    let nix = nix_setup_script();
    let workspace = workspace_bootstrap_script();
    for shared in ["egress_gate() {", "1.1.1.1:443", "8.8.8.8:443"] {
        assert!(
            nix.contains(shared),
            "nix-setup missing gate fragment: {shared}"
        );
        assert!(
            workspace.contains(shared),
            "workspace missing gate fragment: {shared}"
        );
    }
}

#[test]
fn egress_gate_no_ipv6_check_is_gated_on_the_mode_env() {
    // The no-IPv6 assertion must only run when the daemon advertises that
    // posture, so the dual-stack mode (which provisions a ULA deliberately) is
    // not rejected. The IPv6 probe must sit inside the env guard.
    let script = workspace_bootstrap_script();
    assert!(
        script.contains(AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV),
        "the gate must consult the mode env var before forbidding IPv6"
    );
    let guard = script
        .find(AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV)
        .expect("env guard present");
    let probe = script
        .find("ip -6 addr show scope global")
        .expect("ipv6 probe present");
    assert!(
        guard < probe,
        "the no-IPv6 probe must be guarded by the mode env var"
    );
    // The IPv4-egress probe is unconditional; it must NOT be inside the guard.
    let v4 = script.find("/dev/tcp/").expect("v4 probe present");
    assert!(
        v4 < guard,
        "the IPv4-egress probe must run regardless of the IPv6 mode"
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

/// Both guest scripts are assembled from one shared nix prologue. Assert
/// the security-critical lines — the broker-token guard, the netrc
/// credential write, and the nix.conf trusted-keys / substituter block —
/// appear identically in both, and that the only divergences are the
/// documented three (flakes, the runtime dir, the positional parse). This
/// guards the dedup'd prologue against a future edit silently desyncing
/// the two scripts.
#[test]
fn both_guest_scripts_share_the_nix_prologue() {
    let nix = nix_setup_script();
    let workspace = workspace_bootstrap_script();

    for shared in [
        r#": "${WRIT_BROKER_TOKEN:?}""#,
        r#"  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC""#,
        r#"printf 'build-users-group =\n'"#,
        r#"printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS""#,
        r#"} > "$NIX_CONF_DIR/nix.conf""#,
        // The runtime dir and the egress gate are now shared by both scripts.
        r#""$NIX_CONF_DIR" /run/writ-agent-vm"#,
        "egress_gate() {",
    ] {
        assert!(
            nix.contains(shared),
            "nix script missing shared fragment: {shared}"
        );
        assert!(
            workspace.contains(shared),
            "workspace script missing shared fragment: {shared}"
        );
    }

    // The two remaining documented divergences, and only those: the workspace
    // script enables flakes and parses positional repo/destination/warm args.
    assert!(workspace.contains("nix-command flakes"));
    assert!(!nix.contains("nix-command flakes"));
    assert!(workspace.contains(r#"repo="$1""#));
    assert!(!nix.contains(r#"repo="$1""#));
}
