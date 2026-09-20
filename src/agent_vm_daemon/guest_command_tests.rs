//! Example/edge-case tests for the guest shell scripts and the
//! guest-command builders. The arbitrary-input framing contract
//! lives in the inline `spec` module beside the code.
use super::guest_command::*;
use super::test_support::*;
use super::*;
use crate::agent_vm_guest_log::{GuestBootstrapRecord, GuestBootstrapReport, scan_bootstrap_log};
use crate::vm_git::WorkspaceWarmMode;
use std::fs;
use std::process::Command;

#[test]
fn guest_nix_setup_script_writes_configured_trusted_public_keys() {
    let dir = tempfile::tempdir().unwrap();
    let netrc = dir.path().join("run").join("netrc");
    let nix_conf_dir = dir.path().join("nix-conf");
    let home = dir.path().join("home");
    let trusted_public_keys =
        format!("{TEST_NIX_CACHE_PUBLIC_KEY} {SECOND_TEST_NIX_CACHE_PUBLIC_KEY}");

    let status = writ_core::process_spawn::output(
        Command::new("sh")
            .arg("-c")
            .arg(nix_conf_prologue_script_for_test())
            .arg("writ-agent-vm-nix-setup")
            .arg("true")
            .env("HOME", &home)
            .env("WRIT_BROKER_TOKEN", "writ-vm-token")
            .env(
                "WRIT_NIX_CACHE_URL",
                "http://192.168.252.1:51375/v1/nix/cache",
            )
            .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
            .env("WRIT_NIX_NETRC", &netrc)
            .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, &trusted_public_keys)
            .env("NIX_CONF_DIR", &nix_conf_dir),
    )
    .unwrap()
    .status;

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
fn guest_nix_setup_script_writes_claude_default_settings() {
    let dir = tempfile::tempdir().unwrap();
    let netrc = dir.path().join("run").join("netrc");
    let nix_conf_dir = dir.path().join("nix-conf");
    let home = dir.path().join("home");

    let status = writ_core::process_spawn::output(
        Command::new("sh")
            .arg("-c")
            .arg(nix_conf_prologue_script_for_test())
            .arg("writ-agent-vm-nix-setup")
            .arg("true")
            .env("HOME", &home)
            .env("WRIT_BROKER_TOKEN", "writ-vm-token")
            .env(
                "WRIT_NIX_CACHE_URL",
                "http://192.168.252.1:51375/v1/nix/cache",
            )
            .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
            .env("WRIT_NIX_NETRC", &netrc)
            .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, "")
            .env("NIX_CONF_DIR", &nix_conf_dir),
    )
    .unwrap()
    .status;

    assert!(status.success());
    let settings_path = home.join(".claude").join("settings.json");
    let settings = fs::read_to_string(&settings_path).unwrap();
    assert_eq!(
        settings,
        r#"{"env":{"CLAUDE_AFK_TIMEOUT_MS":"86400000","CLAUDE_CODE_DISABLE_CRON":"1","CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY":"1"},"sandbox":{"enabled":false,"allowUnsandboxedCommands":true},"defaultMode":"bypassPermissions","skipDangerousModePermissionPrompt":true}
"#
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let settings_mode = fs::metadata(settings_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(settings_mode, 0o600);
    }
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
    let home = dir.path().join("home");

    let status = writ_core::process_spawn::output(
        Command::new("sh")
            .arg("-c")
            .arg(nix_conf_prologue_script_for_test())
            .arg("writ-agent-vm-nix-setup")
            .arg("true")
            .env("HOME", &home)
            .env("WRIT_BROKER_TOKEN", "writ-vm-token")
            .env(
                "WRIT_NIX_CACHE_URL",
                "http://192.168.252.1:51375/v1/nix/cache",
            )
            .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
            .env("WRIT_NIX_NETRC", &netrc)
            .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, "")
            .env("NIX_CONF_DIR", &nix_conf_dir),
    )
    .unwrap()
    .status;

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
fn nix_setup_gates_then_signals_ok_and_runs_command() {
    // The non-workspace path gates on egress too: it waits for broker-ready,
    // runs the same gate (routing a failure through the daemon-polled
    // bootstrap-failed sentinel, like the workspace path), then signals
    // bootstrap-ok and runs the guest command.
    let script = nix_setup_script();
    assert!(
        script.contains(AGENT_VM_WORKSPACE_BROKER_READY_PATH),
        "nix-setup must wait for broker-ready before the gate"
    );
    assert!(
        script.contains("/dev/tcp/") && script.contains("LEAK"),
        "nix-setup must run the egress gate"
    );
    assert!(
        script.contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH),
        "a gate failure must route through the bootstrap-failed sentinel"
    );

    // On success: signal bootstrap-ok, then run the command. As a CHILD, not
    // `exec`, so the container outlives a fast command and the daemon reliably
    // observes bootstrap-ok.
    let gate = script.find("/dev/tcp/").expect("gate present");
    let ok = script
        .find(AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH)
        .expect("bootstrap-ok signal present");
    let run = script.rfind(r#""$@""#).expect("guest command run present");
    assert!(
        gate < ok && ok < run,
        "must pass the gate, then signal bootstrap-ok, then run the command"
    );
    assert!(
        !script.contains(r#"exec "$@""#),
        "must not exec the command — the container must outlive a fast command"
    );
}

#[test]
fn egress_gate_probes_external_dns() {
    // Beyond TCP/443, the gate confirms no external DNS egress — a "allow DNS"
    // firewall leak that the 443 probes miss. A public resolver answering a UDP
    // query on :53 is a leak. Shared by both scripts, part of the unconditional
    // negative control (before the IPv6 mode guard and the workload).
    for script in [workspace_bootstrap_script(), nix_setup_script()] {
        assert!(
            script.contains("/dev/udp/") && script.contains("/53"),
            "gate must probe an external DNS resolver over UDP/53"
        );
        let dns = script.find("/dev/udp/").expect("dns probe present");
        let v6_guard = script
            .find(AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV)
            .expect("ipv6 guard present");
        assert!(
            dns < v6_guard,
            "the DNS probe is unconditional negative control, before the IPv6 mode guard"
        );
    }
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

    let err = wrap_guest_command_with_workspace_bootstrap(
        BootstrapSignals::SentinelFiles,
        &workspace,
        vec!["true".into()],
    )
    .unwrap_err();

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

/// The locked scripts differ from the legacy ones in exactly two things, and
/// both are the channel: how the guest learns the broker is up, and where it
/// reports its outcome.
///
/// Asserted by putting the legacy signalling *back* into the locked script
/// and finding the legacy script — so any *other* divergence, in the nix
/// prologue, the egress gate or the workspace init, fails here. That is the
/// property worth holding: the locked profile changes the channel, not the
/// bootstrap.
#[test]
fn the_locked_scripts_differ_from_the_legacy_ones_only_in_the_channel() {
    for (legacy, locked) in [
        (
            nix_setup_script(),
            nix_setup_script_with_signals(BootstrapSignals::LogRecords),
        ),
        (
            workspace_bootstrap_script(),
            workspace_bootstrap_script_with_signals(BootstrapSignals::LogRecords),
        ),
    ] {
        let restored = locked
            .replace(
                BootstrapSignals::LogRecords.ok(),
                BootstrapSignals::SentinelFiles.ok(),
            )
            .replace(
                BootstrapSignals::LogRecords.fail_sink(),
                BootstrapSignals::SentinelFiles.fail_sink(),
            )
            .replace(BootstrapSignals::LogRecords.prelude(), "");
        // The locked script omits the broker-ready wait entirely, so put it
        // back where the legacy one has it: immediately before the gate.
        let restored = restored.replace(
            "\negress_gate() {",
            &format!(
                "{}\negress_gate() {{",
                BootstrapSignals::SentinelFiles.broker_ready_wait()
            ),
        );
        assert_eq!(restored, legacy);
    }
}

/// A locked script reports through the log channel and touches no sentinel.
#[test]
fn the_locked_scripts_report_through_records_not_sentinels() {
    for script in [
        nix_setup_script_with_signals(BootstrapSignals::LogRecords),
        workspace_bootstrap_script_with_signals(BootstrapSignals::LogRecords),
    ] {
        assert!(
            !script.contains("bootstrap-ok") && !script.contains("bootstrap-failed"),
            "a locked script must not write the daemon-polled sentinels: {script}"
        );
        assert!(script.contains("writ-agent-vm-bootstrap ok"));
        assert!(script.contains("_writ_bootstrap_failed"));
    }
}

/// The success line the locked script prints is exactly the record the host
/// parses, so the two sides of the channel cannot drift.
#[test]
fn the_locked_success_line_is_the_record_the_host_reads() {
    let rendered = GuestBootstrapRecord::Ok.render();
    let script = nix_setup_script_with_signals(BootstrapSignals::LogRecords);
    assert!(
        script.contains(&rendered),
        "the script must print exactly {rendered:?}: {script}"
    );
    assert_eq!(
        scan_bootstrap_log(&rendered),
        Ok(GuestBootstrapReport::Finished(GuestBootstrapRecord::Ok))
    );
}

/// The failure emitter the locked script defines produces a record the host
/// reads, for reasons a guest can actually produce: multi-line, control
/// bytes, non-ASCII, and far too long.
///
/// Run as real shell rather than reasoned about, because the bound is `tr` and
/// `cut` semantics and those are what the guest will execute.
#[test]
fn the_locked_failure_emitter_produces_a_record_the_host_reads() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let script = format!(
        "{}\n_writ_bootstrap_failed\n",
        BootstrapSignals::LogRecords.prelude()
    );
    let path = crate::test_support::write_executable_script(dir.path(), "emit.sh", &script);
    let control = format!("a {}[31mcontrol{}[0m sequence", '\u{1b}', '\u{1b}');
    let long = "x".repeat(4000);
    for reason in [
        "workspace init failed with exit 3",
        "line one\nline two\ttabbed",
        control.as_str(),
        "naive unicode \u{2026} reason",
        long.as_str(),
    ] {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = writ_core::process_spawn::spawn(&mut command).expect("the emitter runs");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(reason.as_bytes())
            .unwrap();
        let output = child.wait_with_output().expect("the emitter finishes");
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        let scanned = scan_bootstrap_log(&printed);
        assert!(
            matches!(
                scanned,
                Ok(GuestBootstrapReport::Finished(
                    GuestBootstrapRecord::Failed { .. }
                ))
            ),
            "reason {reason:?} printed {printed:?}, scanned {scanned:?}"
        );
    }
}

/// A locked script waits for no broker-ready file. Nothing in the locked
/// start creates one — being released *is* that signal — so a script that
/// waited would block forever on a file that never appears.
#[test]
fn the_locked_scripts_wait_for_no_broker_ready_file() {
    for script in [
        nix_setup_script_with_signals(BootstrapSignals::LogRecords),
        workspace_bootstrap_script_with_signals(BootstrapSignals::LogRecords),
    ] {
        assert!(
            !script.contains("broker-ready"),
            "a locked script must not wait for a file nothing creates: {script}"
        );
    }
    // The legacy scripts still do, because the daemon still touches it.
    for script in [nix_setup_script(), workspace_bootstrap_script()] {
        assert!(script.contains("/run/writ-agent-vm/broker-ready"));
    }
}

/// A bootstrap failure keeps its *tail*, because that is where the actionable
/// error is: a workspace init that fails after a great deal of progress
/// prints the error last, and the sentinel path tails its failure file for
/// exactly this reason.
#[test]
fn a_long_bootstrap_failure_keeps_the_error_at_its_end() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let script = format!(
        "{}\n_writ_bootstrap_failed\n",
        BootstrapSignals::LogRecords.prelude()
    );
    let path = crate::test_support::write_executable_script(dir.path(), "emit.sh", &script);
    let reason = format!(
        "{}\nerror: builder for drv failed with exit code 1",
        "copying path 'nix/store/some-long-progress-line' from cache\n".repeat(40)
    );
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg(&path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = writ_core::process_spawn::spawn(&mut command).expect("the emitter runs");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(reason.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("the emitter finishes");
    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        printed.contains("builder for drv failed with exit code 1"),
        "the actionable error must survive the bound: {printed:?}"
    );
    assert!(matches!(
        scan_bootstrap_log(&printed),
        Ok(GuestBootstrapReport::Finished(
            GuestBootstrapRecord::Failed { .. }
        ))
    ));
}

/// The session's mode decides which channel its scripts report on, so a
/// locked session cannot be started with scripts that write sentinel files
/// the host will never come back to read — nor a legacy one with records
/// nobody reads.
///
/// Asserted through [`wrap_guest_command`], the production entry point,
/// rather than against the selector, so what is checked is the script a
/// session would actually be given.
#[test]
fn the_mode_decides_which_channel_a_session_reports_on() {
    for mode in Ipv6IsolationMode::ALL {
        let locked = mode == Ipv6IsolationMode::Ipv4OnlyLockedV1;
        let script = wrap_guest_command(mode, None, vec!["true".into()])
            .unwrap()
            .join("\n");
        assert_eq!(
            script.contains(crate::agent_vm_guest_log::BOOTSTRAP_RECORD_PREFIX),
            locked,
            "{mode:?} should{} report through records",
            if locked { "" } else { " not" }
        );
        assert_eq!(
            script.contains("touch /run/writ-agent-vm/bootstrap-ok"),
            !locked,
            "{mode:?} should{} write the sentinel files",
            if locked { " not" } else { "" }
        );
        assert_eq!(
            script.contains("/run/writ-agent-vm/broker-ready"),
            !locked,
            "{mode:?} should{} wait for a broker-ready file",
            if locked { " not" } else { "" }
        );
    }
}
