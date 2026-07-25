//! Tests for broker-VM planning, config JSON, secret export, and `container inspect` state parsing. Split out of `broker_vm.rs` (an inline `#[cfg(test)]` module); tests unchanged.

use super::*;
use crate::broker_session::read_bearer_token_file;
use crate::core::Ipv4Cidr;
use std::net::Ipv4Addr;

fn session_id() -> SessionId {
    "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap()
}

fn sample_plan() -> BrokerVmPlan {
    BrokerVmPlan::new(
        session_id(),
        ContainerImage::new("writ-broker-vm:latest").unwrap(),
        "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
        AgentVmResources::new(2, 1024).unwrap(),
        "/usr/local/bin/container",
        "/var/run/writ/broker/51b8/session",
        "/var/lib/writ/secrets",
        "/var/lib/writ/audit",
    )
}

#[test]
fn names_are_session_scoped_and_distinct_from_agent() {
    let names = BrokerVmNames::for_session(session_id());
    assert_eq!(
        names.vm(),
        "writ-broker-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
    );
    assert_eq!(
        names.egress_network(),
        "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
    );
}

#[test]
fn egress_network_is_created_without_internal() {
    let args = sample_plan()
        .create_egress_network_invocation()
        .args_lossy();
    assert_eq!(
        args,
        vec![
            "network",
            "create",
            "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert!(!args.iter().any(|a| a == "--internal"));
}

#[test]
fn internal_network_is_created_internal_with_the_shared_subnet() {
    let args = sample_plan()
        .create_internal_network_invocation()
        .args_lossy();
    assert_eq!(
        args,
        vec![
            "network",
            "create",
            "--internal",
            "--subnet",
            "192.168.252.0/24",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
}

#[test]
fn run_invocation_is_dual_homed_with_mounts_and_broker_command() {
    let plan = sample_plan();
    let inv = plan.run_invocation();
    assert_eq!(inv.program(), Path::new("/usr/local/bin/container"));
    let args = inv.args_lossy();

    // Dual-homed, egress network first so the default route lands on the NAT
    // interface, then the shared internal network.
    let networks: Vec<&String> = args
        .iter()
        .zip(args.iter().skip(1))
        .filter(|(flag, _)| *flag == "--network")
        .map(|(_, name)| name)
        .collect();
    assert_eq!(
        networks,
        vec![
            "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );

    // The three bind mounts, with the secret store read-only.
    assert!(args.contains(&format!(
        "type=virtiofs,source=/var/run/writ/broker/51b8/session,target={BROKER_VM_SESSION_DIR}"
    )));
    assert!(args.contains(&format!(
        "type=virtiofs,source=/var/lib/writ/secrets,target={BROKER_VM_SECRETS_DIR},readonly"
    )));
    assert!(args.contains(&format!(
        "type=virtiofs,source=/var/lib/writ/audit,target={BROKER_VM_AUDIT_DIR}"
    )));

    // Detached, correct image, then the route-fix prologue wrapping the
    // writd broker command pointing at the mounted material.
    let image_at = args
        .iter()
        .position(|a| a == "writ-broker-vm:latest")
        .unwrap();
    assert_eq!(args[image_at - 1], "-d");
    assert_eq!(
        &args[image_at + 1..image_at + 6],
        &[
            "sh".to_string(),
            "-c".to_string(),
            BROKER_VM_ROUTE_FIX_SCRIPT.to_string(),
            "writ-broker-route-fix".to_string(),
            "192.168.252.0/24".to_string(),
        ]
    );
    // Changing this argv is a host↔broker contract change: bump
    // `BROKER_PROTOCOL_VERSION` and rebuild the broker image (see
    // `broker_contract_fingerprint_is_pinned`).
    assert_eq!(
        &args[image_at + 6..],
        &[
            "writd".to_string(),
            "broker".to_string(),
            "--config".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/config.json"),
            "--session-spec".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/session-spec.json"),
            "--bearer-token-file".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/bearer-token"),
        ]
    );
}

/// The guest-facing route surface, digested, once per contract version.
///
/// **Append a row when the routes change; never edit one.** The test below
/// asserts the live route digest equals the row at index
/// `VM_HTTP_CONTRACT_VERSION - 1`, that the history has exactly that many rows,
/// and that no digest repeats. So moving a path fails until a *new* row is
/// appended with a bumped version — and the only way to make it pass without
/// bumping is to overwrite a recorded historical digest, which is a conspicuous
/// diff rather than the innocuous "update the snapshot" it used to be.
///
/// (A golden test cannot make the wrong repair *impossible* — a determined edit
/// always can. What it can do is make the right repair the easy one and the
/// wrong one visible in review. That distinction was worth being precise about:
/// an earlier draft listed the version and the routes as independent fields,
/// which let a route change be absorbed by editing the route text alone.)
const GUEST_ROUTE_DIGEST_HISTORY: &[&str] = &[
    // v1 — the pre-split surface, retired by the vendor namespaces. Its digest
    // was never recorded (the history starts here), so this is a placeholder
    // standing in for "some surface that is not any later one". It is only ever
    // compared for distinctness; the live digest is always checked against the
    // row for the *current* version.
    "v1-unrecorded-pre-vendor-namespace-surface",
    // v2 — vendor namespaces (`/anthropic/v1/*`, `/openai/v1/*`).
    "1d9660853cccc4397d1ec7d22cb1c5331a1b9707615d01ca677d7f351d5621e1",
];

fn guest_route_digest() -> String {
    let routes: Vec<String> = crate::vm_http::route_table::tests::ENDPOINT_MAP
        .iter()
        .map(|(method, target, _)| format!("{method} {target}"))
        .collect();
    writ_agent_run::sha256_hex(routes.join("\n").as_bytes())
}

/// CI pin for the guest/broker contract. It combines the broker CLI flag names
/// the host passes, the on-disk schema of the ready document, and the
/// guest-facing route surface (via [`GUEST_ROUTE_DIGEST_HISTORY`]). If you change
/// any of them — add/rename a broker CLI flag, change `BrokerReadyDoc`'s shape
/// (the exhaustive struct literal below fails to compile on a field addition), or
/// move a guest-visible path — this test fails and names the constant to bump.
///
/// It gates **two** version constants, because one contract surface gates two
/// independently-rebuildable images: `BROKER_PROTOCOL_VERSION` forces the broker
/// VM image to be rebuilt (host↔broker axis) and `VM_HTTP_CONTRACT_VERSION` the
/// guest image (guest↔broker axis, checked by the guest at startup). A
/// guest-visible change generally moves both.
///
/// The route surface is covered here because leaving it out let two real defects
/// through: the vendor namespaces changed every guest URL, and `/v1/session`
/// began reporting a contract version — both without a bump, so a stale image
/// would have been accepted as compatible. A path change *is* a contract change.
/// The session-spec schema is guarded independently by its own `version` field
/// and the `broker_session` tests.
#[test]
fn broker_contract_fingerprint_is_pinned() {
    let args = sample_plan().run_invocation().args_lossy();
    let broker_at = args
        .iter()
        .position(|a| a == "broker")
        .expect("broker subcommand present");
    let flags: Vec<&str> = args[broker_at..]
        .iter()
        .filter(|a| a.starts_with("--"))
        .map(String::as_str)
        .collect();

    // A fully-populated ready doc pins the field names and which fields
    // serialize; the exhaustive literal forces an update on a field addition.
    // `protocol_version` is sourced from the real constant (not a literal), so
    // bumping `BROKER_PROTOCOL_VERSION` alone breaks this snapshot too — the
    // token cannot silently drift from the version the broker actually stamps.
    let ready_doc = crate::broker_protocol::BrokerReadyDoc {
        protocol_version: crate::broker_protocol::BROKER_PROTOCOL_VERSION,
        broker_port: 18080,
        writd_build: Some("pinned".to_string()),
    };
    let fingerprint = format!(
        "broker-cli-flags: {}\nready-doc: {}",
        flags.join(" "),
        serde_json::to_string(&ready_doc).unwrap(),
    );

    assert_eq!(
        fingerprint,
        "broker-cli-flags: --config --session-spec --bearer-token-file\n\
         ready-doc: {\"protocol_version\":4,\"broker_port\":18080,\"writd_build\":\"pinned\"}",
        "the host↔broker contract changed. Update this snapshot AND bump \
         BROKER_PROTOCOL_VERSION (and rebuild the broker image)."
    );

    // The guest route surface, coupled to the guest contract version: the live
    // digest must be the row this version recorded.
    let version = crate::vm_git::VM_HTTP_CONTRACT_VERSION as usize;
    assert_eq!(
        GUEST_ROUTE_DIGEST_HISTORY.len(),
        version,
        "VM_HTTP_CONTRACT_VERSION is {version} but the route-digest history has {} row(s): \
         append exactly one row per version",
        GUEST_ROUTE_DIGEST_HISTORY.len(),
    );
    assert_eq!(
        guest_route_digest(),
        GUEST_ROUTE_DIGEST_HISTORY[version - 1],
        "the guest-facing route surface changed. Append its new digest to \
         GUEST_ROUTE_DIGEST_HISTORY, bump VM_HTTP_CONTRACT_VERSION (so guests refuse a stale \
         broker) AND bump BROKER_PROTOCOL_VERSION (so the host refuses a stale broker image), \
         then rebuild both images.",
    );
    let unique: std::collections::BTreeSet<&&str> = GUEST_ROUTE_DIGEST_HISTORY.iter().collect();
    assert_eq!(
        unique.len(),
        GUEST_ROUTE_DIGEST_HISTORY.len(),
        "a route digest is repeated: two contract versions cannot describe the same surface",
    );
}

#[test]
fn logs_invocation_requests_a_bounded_tail() {
    // The crash-log capture must ask the container tool for only the last N
    // lines, so a broker that emitted a huge log before crashing cannot force
    // the host to buffer it all.
    let args = sample_plan().logs_invocation().args_lossy();
    assert_eq!(args[0], "logs");
    assert_eq!(args[1], "-n");
    assert_eq!(args[2], BROKER_LOG_TAIL_LINES.to_string());
    assert!(
        args[3].starts_with("writ-broker-vm-"),
        "last arg must be the broker VM name: {args:?}"
    );
    assert_eq!(args.len(), 4);
}

#[test]
fn route_fix_prologue_targets_the_internal_subnet_and_demotes_it() {
    // The prologue must receive the internal CIDR and drop default routes on
    // the matching interface, so the broker's egress survives dual-homing.
    assert!(BROKER_VM_ROUTE_FIX_SCRIPT.contains("ip route del default dev"));
    // Must use only tools the production guest image allows: no awk/grep/sed
    // (forbidden), and no `set -e` (so a no-match can't abort before exec).
    for forbidden in ["awk", "grep", "sed", "set -e"] {
        assert!(
            !BROKER_VM_ROUTE_FIX_SCRIPT.contains(forbidden),
            "route-fix prologue must not use {forbidden:?}"
        );
    }
    let args = sample_plan().run_invocation().args_lossy();
    let fix_at = args
        .iter()
        .position(|a| a == "writ-broker-route-fix")
        .expect("route-fix prologue is present");
    assert_eq!(args[fix_at + 1], "192.168.252.0/24");
}

#[test]
fn stop_invocations_remove_vm_then_egress_then_shared_internal_network() {
    let stops: Vec<Vec<String>> = sample_plan()
        .stop_invocations()
        .iter()
        .map(ProcessInvocation::args_lossy)
        .collect();
    assert_eq!(
        stops,
        vec![
            vec![
                "rm".to_string(),
                "-f".to_string(),
                "writ-broker-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
            ],
            vec![
                "network".to_string(),
                "rm".to_string(),
                "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
            ],
            vec![
                "network".to_string(),
                "rm".to_string(),
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
            ],
        ]
    );
}

#[test]
fn removal_invocations_from_identity_match_the_plan_in_order() {
    // The daemon cleanup and dry-run reconstruct teardown from session
    // identity; it must be exactly the plan's stop sequence, in order: broker
    // VM, egress network, shared internal network.
    let plan = sample_plan();
    let names = BrokerVmNames::for_session(session_id());
    let from_identity = broker_vm_removal_invocations(
        Path::new("/usr/local/bin/container"),
        &names,
        "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
    );
    let args = |invs: &[ProcessInvocation]| -> Vec<Vec<String>> {
        invs.iter().map(ProcessInvocation::args_lossy).collect()
    };
    assert_eq!(args(&from_identity), args(&plan.stop_invocations()));
    assert_eq!(
        args(&from_identity),
        vec![
            vec![
                "rm".to_string(),
                "-f".to_string(),
                format!("writ-broker-vm-{}", session_id())
            ],
            vec![
                "network".to_string(),
                "rm".to_string(),
                format!("writ-broker-egress-{}", session_id())
            ],
            vec![
                "network".to_string(),
                "rm".to_string(),
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string()
            ],
        ]
    );
}

#[test]
fn session_paths_are_one_per_session_dir_with_known_mounts() {
    let paths = BrokerVmSessionPaths::new(Path::new("/var/lib/writ/broker-vm"), session_id());
    assert_eq!(
        paths.session_dir(),
        Path::new("/var/lib/writ/broker-vm/51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d")
    );
    // staging + secrets both live under the one per-session dir, so removing
    // session_dir() removes everything (copied secrets included).
    assert!(paths.staging_dir().starts_with(paths.session_dir()));
    assert!(paths.secrets_dir().starts_with(paths.session_dir()));
    assert_ne!(paths.staging_dir(), paths.secrets_dir());
}

#[test]
fn broker_url_is_http_ip_port() {
    let url = broker_url(
        Ipv4Addr::new(192, 168, 252, 3),
        BrokerPort::new(18080).unwrap(),
    );
    assert_eq!(url, "http://192.168.252.3:18080/");
}

/// Shape captured verbatim from `container inspect` (Apple container 1.0.0) on
/// a running VM: an array of one container with `status.networks[]` entries
/// carrying `network` + `ipv4Address` (`addr/prefix`).
fn inspect_json(networks: &str) -> String {
    format!(
        r#"[
          {{
            "id": "writ-broker-vm-abc",
            "status": {{
              "networks": [{networks}],
              "startedDate": "2026-06-22T17:01:04Z",
              "state": "running"
            }}
          }}
        ]"#
    )
}

#[test]
fn parses_broker_ipv4_on_the_internal_network() {
    // Two attachments (egress + internal); must pick the internal one.
    let json = inspect_json(
        r#"
        {"network":"writ-broker-egress-abc","ipv4Address":"192.168.64.5/24","ipv4Gateway":"192.168.64.1"},
        {"network":"writ-net","ipv4Address":"192.168.252.3/24","ipv4Gateway":"192.168.252.1","macAddress":"fe:6c:2d:f5:08:69","mtu":1280}
        "#,
    );
    let ip = parse_broker_ipv4_on_network(&json, "writ-net").unwrap();
    assert_eq!(ip, Ipv4Addr::new(192, 168, 252, 3));
}

#[test]
fn missing_network_is_an_error() {
    let json =
        inspect_json(r#"{"network":"writ-broker-egress-abc","ipv4Address":"192.168.64.5/24"}"#);
    assert_eq!(
        parse_broker_ipv4_on_network(&json, "writ-net"),
        Err(BrokerInspectError::NetworkNotFound("writ-net".to_string()))
    );
}

#[test]
fn stopped_container_has_no_running_attachment() {
    // `status.networks` is empty until the container is running.
    let json = inspect_json("");
    assert_eq!(
        parse_broker_ipv4_on_network(&json, "writ-net"),
        Err(BrokerInspectError::NetworkNotFound("writ-net".to_string()))
    );
}

#[test]
fn missing_or_invalid_address_is_an_error() {
    let no_addr = inspect_json(r#"{"network":"writ-net","ipv4Gateway":"192.168.252.1"}"#);
    assert_eq!(
        parse_broker_ipv4_on_network(&no_addr, "writ-net"),
        Err(BrokerInspectError::MissingAddress {
            network: "writ-net".to_string()
        })
    );
    let bad_addr = inspect_json(r#"{"network":"writ-net","ipv4Address":"not-an-ip/24"}"#);
    assert!(matches!(
        parse_broker_ipv4_on_network(&bad_addr, "writ-net"),
        Err(BrokerInspectError::InvalidAddress { .. })
    ));
}

#[test]
fn non_json_is_an_error() {
    assert!(matches!(
        parse_broker_ipv4_on_network("not json", "writ-net"),
        Err(BrokerInspectError::Json(_))
    ));
    assert_eq!(
        parse_broker_ipv4_on_network("[]", "writ-net"),
        Err(BrokerInspectError::NoContainer)
    );
}

#[test]
fn parse_broker_state_reads_running() {
    assert_eq!(
        parse_broker_state(&inspect_json("")),
        BrokerVmState::Running
    );
}

#[test]
fn parse_broker_state_classifies_stopped_like_states_as_terminal() {
    for terminal in ["stopped", "exited", "failed"] {
        let json = format!(r#"[{{"status":{{"state":"{terminal}"}}}}]"#);
        assert_eq!(
            parse_broker_state(&json),
            BrokerVmState::Terminal(terminal.to_string()),
            "state {terminal:?} should be terminal"
        );
    }
}

#[test]
fn parse_broker_state_is_unknown_for_transient_or_absent_states() {
    // Transient states, an empty container list, missing state, and unparseable
    // JSON must all degrade to Unknown so the readiness wait keeps polling
    // rather than falsely declaring the broker crashed.
    for json in [
        r#"[{"status":{"state":"creating"}}]"#,
        r#"[{"status":{"state":"stopping"}}]"#,
        r#"[{"status":{}}]"#,
        "[]",
        "not json",
    ] {
        assert_eq!(
            parse_broker_state(json),
            BrokerVmState::Unknown,
            "json {json:?} should be Unknown"
        );
    }
}

/// A host daemon config whose `vm_http` sets host-path-only features (a
/// prewarm dir, a mirror cache, host staging roots) that must not survive
/// into the broker VM.
fn host_config_json() -> String {
    r#"{
        "github_apps": { "claude": {
            "app_id": 1, "installation_id": 2,
            "installation_owner": "o", "private_key_secret": "pk"
        } },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "audit_db": "/Users/me/Library/writ/audit.db",
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16",
                "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252,
                "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest",
                "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0",
                "broker_port_min": 18080,
                "broker_port_max": 18090,
                "git_program": "/usr/bin/git",
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/Users/me/Library/writ/git-work",
                "clone_timeout_secs": 30,
                "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576,
                "nix_cache_max_nar_bytes": 67108864,
                "nix_prewarm_cache_dir": "/Users/me/Library/writ/prewarm",
                "flake_mirror_cache_dir": "/Users/me/Library/writ/mirror",
                "agent_run_log_root": "/Users/me/Library/writ/agent-runs",
                "git_push_staging_root": "/Users/me/Library/writ/git-push"
            }
        }
    }"#
    .to_string()
}

#[test]
fn broker_config_rewrites_paths_pins_port_and_drops_host_features() {
    use crate::config::{DaemonConfig, SecretStoreConfig};

    // A path that does NOT yet exist, so `to_runtime_config` creates it 0700
    // (as it does for the real guest work_root); a pre-existing 0755 dir is
    // correctly rejected as insecure.
    let tmp = tempfile::tempdir().unwrap();
    let work_root = tmp.path().join("broker-work");
    let json = broker_config_json(
        &host_config_json(),
        BrokerPort::new(18080).unwrap(),
        work_root.to_str().unwrap(),
        Path::new("/Users/me/Library/writ/audit.db"),
    )
    .unwrap();

    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    // Secrets and audit point at the mounted guest locations.
    match config.secret_store {
        SecretStoreConfig::File { ref path } => {
            assert_eq!(path.to_str().unwrap(), BROKER_VM_SECRETS_DIR)
        }
        other => panic!("expected a file secret store, got {other:?}"),
    }
    assert_eq!(
        config.audit_db.as_deref(),
        Some(Path::new("/writ/audit/audit.db"))
    );

    // The vm_http config is one the broker accepts (the strong oracle), the
    // port is pinned, and the host-only features are gone.
    let vm_http = config.agent_vm.expect("agent_vm present").vm_http;
    // Executables point at the broker image's guest paths, not the host's.
    assert_eq!(vm_http.git_program, PathBuf::from(BROKER_VM_GIT_PROGRAM));
    assert_eq!(vm_http.nix_program, PathBuf::from(BROKER_VM_NIX_PROGRAM));
    assert_eq!(
        vm_http.askpass_program,
        PathBuf::from(BROKER_VM_ASKPASS_PROGRAM)
    );
    let runtime = vm_http.to_runtime_config().unwrap();
    let fixed = BrokerPort::new(18080).unwrap();
    assert!(runtime.broker_port_range().contains(fixed));
    assert!(
        !runtime
            .broker_port_range()
            .contains(BrokerPort::new(18090).unwrap())
    );
    assert_eq!(
        runtime.nix_prewarm_cache_dir(),
        Some(Path::new(BROKER_VM_PREWARM_DIR)),
        "the host's pre-warm dir must be re-pointed at its read-only guest mount"
    );
    // Flake provisioning is ENABLED in the broker VM (re-pointed mirror cache):
    // the no-egress agent VM gets its locked flake inputs from the broker.
    assert!(
        runtime.flake_provision().is_some(),
        "flake provisioning must be enabled in the broker VM"
    );
}

#[test]
fn broker_config_enables_flake_provisioning_under_the_guest_work_root() {
    use crate::config::DaemonConfig;
    // The mirror cache (which enables provisioning and is retained by clone)
    // must land under the guest work_root, not a host path.
    let json = broker_config_json(
        &host_config_json(),
        BrokerPort::new(18080).unwrap(),
        BROKER_VM_WORK_ROOT,
        Path::new("/var/lib/writ/audit.db"),
    )
    .unwrap();
    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        config
            .agent_vm
            .unwrap()
            .vm_http
            .flake_mirror_cache_dir
            .as_deref(),
        Some(Path::new("/tmp/writ-broker-work/flake-mirror")),
    );
}

#[test]
fn broker_config_repoints_prewarm_dir_at_the_guest_mount() {
    use crate::config::DaemonConfig;
    // The host set nix_prewarm_cache_dir to a host path; the broker must see it
    // re-pointed at the read-only guest mount so it serves the pre-warmed
    // closure local-first (mirrors flake_mirror_cache_dir).
    let json = broker_config_json(
        &host_config_json(),
        BrokerPort::new(18080).unwrap(),
        BROKER_VM_WORK_ROOT,
        Path::new("/var/lib/writ/audit.db"),
    )
    .unwrap();
    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        config
            .agent_vm
            .unwrap()
            .vm_http
            .nix_prewarm_cache_dir
            .as_deref(),
        Some(Path::new(BROKER_VM_PREWARM_DIR)),
    );
}

#[test]
fn broker_config_drops_prewarm_dir_when_host_has_none() {
    use crate::config::DaemonConfig;
    // A host that configured no pre-warm dir leaves the broker with none, so no
    // pre-warm route is served (and no mount is added) — identical to before.
    let host = host_config_json().replace(
        "\"nix_prewarm_cache_dir\": \"/Users/me/Library/writ/prewarm\",\n",
        "",
    );
    assert!(
        !host.contains("nix_prewarm_cache_dir"),
        "test setup removed the pre-warm dir"
    );
    let json = broker_config_json(
        &host,
        BrokerPort::new(18080).unwrap(),
        BROKER_VM_WORK_ROOT,
        Path::new("/var/lib/writ/audit.db"),
    )
    .unwrap();
    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    assert!(
        config
            .agent_vm
            .unwrap()
            .vm_http
            .nix_prewarm_cache_dir
            .is_none(),
    );
}

#[test]
fn with_prewarm_cache_mount_adds_a_readonly_mount_when_set() {
    let plan = sample_plan()
        .with_prewarm_cache_mount(Some(PathBuf::from("/Users/me/Library/writ/prewarm")));
    let args = plan.run_invocation().args_lossy();
    assert!(
        args.contains(&format!(
            "type=virtiofs,source=/Users/me/Library/writ/prewarm,target={BROKER_VM_PREWARM_DIR},readonly"
        )),
        "the host pre-warm dir must be bind-mounted read-only: {args:?}"
    );
}

#[test]
fn with_prewarm_cache_mount_none_adds_no_mount() {
    let plan = sample_plan().with_prewarm_cache_mount(None);
    let args = plan.run_invocation().args_lossy();
    assert!(
        !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
        "no pre-warm dir configured means no pre-warm mount: {args:?}"
    );
}

#[test]
fn broker_config_uses_the_effective_audit_db_basename_over_the_config_field() {
    use crate::config::DaemonConfig;
    // The host config field says `audit.db`, but the *effective* audit DB
    // (e.g. selected via `--audit-db`) has a different basename. The broker
    // must follow the effective path — the file the host opened the session
    // in — not the stale config field.
    let json = broker_config_json(
        &host_config_json(),
        BrokerPort::new(18080).unwrap(),
        "/tmp/x",
        Path::new("/var/run/writ/sessions.sqlite"),
    )
    .unwrap();
    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        config.audit_db.as_deref(),
        Some(Path::new("/writ/audit/sessions.sqlite"))
    );
}

#[test]
fn broker_config_pins_token_env_to_the_image_askpass_var() {
    use crate::config::DaemonConfig;
    // A custom host token_env must be rewritten to the var the broker image's
    // fixed askpass reads, else git gets no password in the broker VM.
    let host = host_config_json().replace(
        r#""git_clone_base_url": "https://github.com","#,
        r#""git_clone_base_url": "https://github.com", "token_env": "CUSTOM_TOKEN","#,
    );
    assert!(
        host.contains("CUSTOM_TOKEN"),
        "test setup injected token_env"
    );
    let json = broker_config_json(
        &host,
        BrokerPort::new(18080).unwrap(),
        "/tmp/x",
        Path::new("/var/lib/writ/audit.db"),
    )
    .unwrap();
    let config: DaemonConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        config.agent_vm.unwrap().vm_http.token_env,
        BROKER_VM_GIT_TOKEN_ENV
    );
}

#[test]
fn broker_config_requires_a_vm_http_section() {
    let no_vm_http = r#"{
        "github_apps": {},
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" }
    }"#;
    assert!(matches!(
        broker_config_json(
            no_vm_http,
            BrokerPort::new(18080).unwrap(),
            "/tmp/x",
            Path::new("/var/lib/writ/audit.db"),
        ),
        Err(BrokerConfigError::MissingVmHttp)
    ));
}

/// Two GitHub apps that *share* a private-key secret (so dedup is exercised)
/// plus a claude proxy with its own auth secret.
fn secret_config() -> crate::config::DaemonConfig {
    let json = r#"{
        "github_apps": {
            "claude": { "app_id": 1, "installation_id": 2,
                        "installation_owner": "o", "private_key_secret": "claude-pk" },
            "codex":  { "app_id": 3, "installation_id": 4,
                        "installation_owner": "o", "private_key_secret": "codex-pk" }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252, "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                "claude_proxy": {
                    "upstream_base_url": "https://api.anthropic.com",
                    "auth_secret": "anthropic-api-key", "auth_kind": "x_api_key",
                    "anthropic_version": "2023-06-01", "timeout_secs": 60,
                    "max_request_bytes": 2097152, "max_response_bytes": 8388608
                }
            }
        }
    }"#;
    serde_json::from_str(json).unwrap()
}

fn secret_strs(config: &crate::config::DaemonConfig, agent: AgentKind) -> Vec<String> {
    broker_secret_keys(config, agent)
        .unwrap()
        .iter()
        .map(|k| k.as_str().to_string())
        .collect()
}

#[test]
fn broker_secret_keys_for_claude_selects_only_the_claude_app_and_proxy() {
    // Claude session: its app key + the claude proxy secret; never codex's
    // app key (the broker can't mint with it).
    assert_eq!(
        secret_strs(&secret_config(), AgentKind::Claude),
        vec!["claude-pk", "anthropic-api-key"]
    );
}

#[test]
fn broker_secret_keys_for_codex_selects_only_the_codex_app() {
    // Codex session: its app key only (secret_config has no openai proxy).
    // Crucially excludes claude-pk and the anthropic proxy secret.
    assert_eq!(
        secret_strs(&secret_config(), AgentKind::Codex),
        vec!["codex-pk"]
    );
}

#[test]
fn broker_secret_keys_rejects_chatgpt_oauth_for_vm_brokers() {
    // A codex session whose openai proxy refreshes its token by writing the
    // secret store can't be served by a read-only ephemeral export.
    let json = r#"{
        "github_apps": { "codex": { "app_id": 1, "installation_id": 2,
            "installation_owner": "o", "private_key_secret": "codex-pk" } },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252, "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                "openai_proxy": {
                    "upstream_base_url": "https://chatgpt.com/backend-api/codex",
                    "auth_secret": "chatgpt-bundle", "auth_kind": "chatgpt_oauth",
                    "timeout_secs": 60, "max_request_bytes": 2097152,
                    "max_response_bytes": 8388608
                }
            }
        }
    }"#;
    let config: crate::config::DaemonConfig = serde_json::from_str(json).unwrap();
    assert_eq!(
        broker_secret_keys(&config, AgentKind::Codex),
        Err(BrokerSecretSelectionError::ChatgptOauthUnsupported)
    );
}

#[test]
fn export_broker_secrets_copies_only_the_needed_keys() {
    let host_dir = tempfile::tempdir().unwrap();
    let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
    host.put(&SecretKey::new("claude-pk").unwrap(), "PEM-DATA")
        .unwrap();
    host.put(&SecretKey::new("anthropic-api-key").unwrap(), "sk-abc")
        .unwrap();
    host.put(&SecretKey::new("codex-pk").unwrap(), "other")
        .unwrap();

    let dest_dir = tempfile::tempdir().unwrap();
    let dest_store = dest_dir.path().join("secrets");
    let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
    export_broker_secrets(&host, &keys, &dest_store).unwrap();

    let injected = FileSecretStore::open(dest_store).unwrap();
    assert_eq!(
        injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
        Some("PEM-DATA".to_string())
    );
    assert_eq!(
        injected
            .get(&SecretKey::new("anthropic-api-key").unwrap())
            .unwrap(),
        Some("sk-abc".to_string())
    );
    // The other agent's app key is never copied into a Claude session's VM.
    assert_eq!(
        injected.get(&SecretKey::new("codex-pk").unwrap()).unwrap(),
        None
    );
}

#[test]
fn export_broker_secrets_fails_on_a_missing_secret_and_leaves_no_store() {
    let host_dir = tempfile::tempdir().unwrap();
    let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
    // host is missing `claude-pk` and `anthropic-api-key`.
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("secrets");
    let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
    assert!(matches!(
        export_broker_secrets(&host, &keys, &dest),
        Err(BrokerSecretExportError::Missing(key)) if key == "claude-pk"
    ));
    // A failed export must not leave a (partial) store to be mounted.
    assert!(!dest.exists(), "partial store must be removed on failure");
}

#[test]
fn export_broker_secrets_clears_a_reused_store_of_stale_secrets() {
    let host_dir = tempfile::tempdir().unwrap();
    let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
    host.put(&SecretKey::new("claude-pk").unwrap(), "PEM-DATA")
        .unwrap();
    host.put(&SecretKey::new("anthropic-api-key").unwrap(), "sk-abc")
        .unwrap();

    // A prior attempt left a now-unneeded secret in the export dir.
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("secrets");
    {
        let stale = FileSecretStore::create_or_open(dest.clone()).unwrap();
        stale
            .put(&SecretKey::new("stale-key").unwrap(), "leftover")
            .unwrap();
    }

    let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
    export_broker_secrets(&host, &keys, &dest).unwrap();

    let injected = FileSecretStore::open(dest).unwrap();
    assert_eq!(
        injected.get(&SecretKey::new("stale-key").unwrap()).unwrap(),
        None,
        "stale secret from a prior attempt must be cleared"
    );
    assert_eq!(
        injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
        Some("PEM-DATA".to_string())
    );
}

#[test]
fn written_material_round_trips_through_the_slice3_readers() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("session");
    let spec = BrokerSessionSpec::new(
        session_id(),
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
        Ipv4Addr::UNSPECIFIED,
        BrokerPort::new(18080).unwrap(),
        GuestAbsPath::new("/writ/session/ready").unwrap(),
        GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
    );
    let bearer = VmHttpBearerToken::generate();
    write_session_material(&staging, &spec, &bearer).unwrap();

    let read_spec = BrokerSessionSpec::read_file(&staging.join("session-spec.json")).unwrap();
    assert_eq!(read_spec, spec);
    let read_bearer = read_bearer_token_file(&staging.join("bearer-token")).unwrap();
    assert_eq!(read_bearer.as_str(), bearer.as_str());
}

#[cfg(unix)]
#[test]
fn reused_staging_dir_clears_ready_and_reforces_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("session");
    let spec = BrokerSessionSpec::new(
        session_id(),
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
        Ipv4Addr::UNSPECIFIED,
        BrokerPort::new(18080).unwrap(),
        GuestAbsPath::new("/writ/session/ready").unwrap(),
        GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
    );
    // First launch, then simulate a prior run leaving a stale ready marker
    // and a world-readable bearer token (e.g. a crashed/retried attempt).
    write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
    std::fs::write(staging.join("ready"), "18080\n").unwrap();
    std::fs::set_permissions(
        staging.join("bearer-token"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    // Re-materialising for the retry must clear the stale marker and tighten
    // perms back to 0600.
    write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
    assert!(
        !staging.join("ready").exists(),
        "stale ready marker must be cleared before relaunch"
    );
    let token_mode = std::fs::metadata(staging.join("bearer-token"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(token_mode, 0o600, "overwrite must re-force 0600");
}

#[cfg(unix)]
#[test]
fn written_material_is_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("session");
    let spec = BrokerSessionSpec::new(
        session_id(),
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
        Ipv4Addr::UNSPECIFIED,
        BrokerPort::new(18080).unwrap(),
        GuestAbsPath::new("/writ/session/ready").unwrap(),
        GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
    );
    write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
    let dir_mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "staging dir must be private");
    let spec_mode = std::fs::metadata(staging.join("session-spec.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(spec_mode, 0o600, "session spec must be private");
    let token_mode = std::fs::metadata(staging.join("bearer-token"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(token_mode, 0o600, "bearer token must be private");
}

// ----- materialize_broker_vm_session ------------------------------------

/// A keyring-backed host config the materializer rewrites for a broker VM: a
/// claude app + claude proxy (a Claude session needs `claude-pk` +
/// `anthropic-api-key`) and a codex app (whose key must NOT enter a Claude
/// VM). Mirrors a real host config so `broker_config_json` is exercised.
fn materialize_host_config_json() -> String {
    r#"{
        "github_apps": {
            "claude": { "app_id": 1, "installation_id": 2,
                        "installation_owner": "o", "private_key_secret": "claude-pk" },
            "codex":  { "app_id": 3, "installation_id": 4,
                        "installation_owner": "o", "private_key_secret": "codex-pk" }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "audit_db": "/Users/me/Library/writ/audit.db",
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252, "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/Users/me/Library/writ/git-work",
                "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                "claude_proxy": {
                    "upstream_base_url": "https://api.anthropic.com",
                    "auth_secret": "anthropic-api-key", "auth_kind": "x_api_key",
                    "anthropic_version": "2023-06-01", "timeout_secs": 60,
                    "max_request_bytes": 2097152, "max_response_bytes": 8388608
                }
            }
        }
    }"#
    .to_string()
}

/// As above but the codex agent's openai proxy refreshes via `chatgpt_oauth`,
/// which a read-only ephemeral export cannot serve — the materializer must
/// reject it before writing anything.
fn chatgpt_oauth_host_config_json() -> String {
    r#"{
        "github_apps": { "codex": { "app_id": 1, "installation_id": 2,
            "installation_owner": "o", "private_key_secret": "codex-pk" } },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "secret_store": { "type": "keyring", "service": "writ" },
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252, "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                "openai_proxy": {
                    "upstream_base_url": "https://chatgpt.com/backend-api/codex",
                    "auth_secret": "chatgpt-bundle", "auth_kind": "chatgpt_oauth",
                    "timeout_secs": 60, "max_request_bytes": 2097152,
                    "max_response_bytes": 8388608
                }
            }
        }
    }"#
    .to_string()
}

fn host_store_with(entries: &[(&str, &str)]) -> (tempfile::TempDir, FileSecretStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSecretStore::create_or_open(dir.path().join("host")).unwrap();
    for (key, value) in entries {
        store.put(&SecretKey::new(*key).unwrap(), value).unwrap();
    }
    (dir, store)
}

fn materialize_request(work: &Path) -> BrokerVmSessionRequest {
    BrokerVmSessionRequest {
        session_id: session_id(),
        agent_kind: AgentKind::Claude,
        image: ContainerImage::new("writ-broker-vm:latest").unwrap(),
        container_tool: PathBuf::from("/usr/local/bin/container"),
        internal_network: "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
        agent_subnet: Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
        bind_addr: Ipv4Addr::UNSPECIFIED,
        broker_port: BrokerPort::new(18080).unwrap(),
        resources: AgentVmResources::new(2, 1024).unwrap(),
        host_audit_db: PathBuf::from("/Users/me/Library/writ/audit.db"),
        staging_dir: work.join("session"),
        secrets_dir: work.join("secrets"),
        audit_dir: work.join("audit"),
    }
}

#[test]
fn materialize_mounts_the_host_prewarm_dir_when_configured() {
    // A host config that sets nix_prewarm_cache_dir at an EXISTING dir must
    // produce a plan that bind-mounts *that host path* read-only into the
    // broker VM, so the re-pointed broker config (which names the guest target)
    // has something to read there.
    let prewarm = tempfile::tempdir().unwrap();
    let prewarm_path = prewarm.path().display().to_string();
    let host_config = materialize_host_config_json().replace(
        "\"nix_cache_max_nar_bytes\": 67108864,",
        &format!(
            "\"nix_cache_max_nar_bytes\": 67108864, \"nix_prewarm_cache_dir\": \"{prewarm_path}\","
        ),
    );
    let (_host_dir, host) = host_store_with(&[
        ("claude-pk", "PEM-DATA"),
        ("anthropic-api-key", "sk-abc"),
        ("codex-pk", "other"),
    ]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    let bearer = VmHttpBearerToken::generate();

    let plan = materialize_broker_vm_session(&request, &host_config, &bearer, &host).unwrap();
    let args = plan.run_invocation().args_lossy();
    assert!(
        args.contains(&format!(
            "type=virtiofs,source={prewarm_path},target={BROKER_VM_PREWARM_DIR},readonly"
        )),
        "the configured host pre-warm dir must be mounted read-only: {args:?}"
    );
}

#[test]
fn materialize_skips_the_prewarm_mount_when_the_host_dir_is_absent() {
    // A configured-but-not-yet-created pre-warm dir is a tolerated state (the
    // validator accepts it). It must NOT crash the broker VM launch by mounting
    // a missing virtiofs source: materialize succeeds and adds no mount, so the
    // broker serves an empty pre-warm cache — as host placement does.
    let host_config = materialize_host_config_json().replace(
        "\"nix_cache_max_nar_bytes\": 67108864,",
        "\"nix_cache_max_nar_bytes\": 67108864, \"nix_prewarm_cache_dir\": \"/no/such/prewarm/dir\",",
    );
    let (_host_dir, host) = host_store_with(&[
        ("claude-pk", "PEM-DATA"),
        ("anthropic-api-key", "sk-abc"),
        ("codex-pk", "other"),
    ]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    let bearer = VmHttpBearerToken::generate();

    let plan = materialize_broker_vm_session(&request, &host_config, &bearer, &host).unwrap();
    let args = plan.run_invocation().args_lossy();
    assert!(
        !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
        "an absent configured pre-warm dir must not be mounted: {args:?}"
    );
}

#[test]
fn materialize_adds_no_prewarm_mount_when_host_has_none() {
    // The default materialize host config sets no pre-warm dir, so the plan
    // carries only the three base mounts — no /writ/prewarm.
    let (_host_dir, host) = host_store_with(&[
        ("claude-pk", "PEM-DATA"),
        ("anthropic-api-key", "sk-abc"),
        ("codex-pk", "other"),
    ]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    let bearer = VmHttpBearerToken::generate();

    let plan =
        materialize_broker_vm_session(&request, &materialize_host_config_json(), &bearer, &host)
            .unwrap();
    let args = plan.run_invocation().args_lossy();
    assert!(
        !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
        "no pre-warm dir configured means no pre-warm mount: {args:?}"
    );
}

#[test]
fn materialize_writes_material_the_broker_readers_accept() {
    let (_host_dir, host) = host_store_with(&[
        ("claude-pk", "PEM-DATA"),
        ("anthropic-api-key", "sk-abc"),
        ("codex-pk", "other"),
    ]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    let bearer = VmHttpBearerToken::generate();
    let token = bearer.as_str().to_string();

    let plan =
        materialize_broker_vm_session(&request, &materialize_host_config_json(), &bearer, &host)
            .unwrap();

    // config.json is exactly what broker_config_json produces (its own
    // correctness is tested separately) and still parses as a broker config.
    let written_config = std::fs::read_to_string(request.staging_dir.join("config.json")).unwrap();
    let expected_config = broker_config_json(
        &materialize_host_config_json(),
        BrokerPort::new(18080).unwrap(),
        BROKER_VM_WORK_ROOT,
        Path::new("/Users/me/Library/writ/audit.db"),
    )
    .unwrap();
    assert_eq!(written_config, expected_config);
    let _: crate::config::DaemonConfig = serde_json::from_str(&written_config).unwrap();

    // The session spec round-trips through the broker's own reader (oracle).
    let spec =
        BrokerSessionSpec::read_file(&request.staging_dir.join("session-spec.json")).unwrap();
    assert_eq!(spec.session_id, session_id());
    assert_eq!(
        spec.agent_ipv4_cidr,
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap()
    );
    assert_eq!(spec.bind_addr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(spec.broker_port, 18080);

    // The bearer token round-trips through the broker's reader.
    let read_bearer = read_bearer_token_file(&request.staging_dir.join("bearer-token")).unwrap();
    assert_eq!(read_bearer.as_str(), token);

    // The exported store holds exactly the Claude session's keys — never the
    // codex app key.
    let injected = FileSecretStore::open(request.secrets_dir.clone()).unwrap();
    assert_eq!(
        injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
        Some("PEM-DATA".to_string())
    );
    assert_eq!(
        injected
            .get(&SecretKey::new("anthropic-api-key").unwrap())
            .unwrap(),
        Some("sk-abc".to_string())
    );
    assert_eq!(
        injected.get(&SecretKey::new("codex-pk").unwrap()).unwrap(),
        None
    );

    // The returned plan mounts those exact dirs and runs `writd broker`.
    let args = plan.run_invocation().args_lossy();
    assert!(args.contains(&format!(
        "type=virtiofs,source={},target={BROKER_VM_SECRETS_DIR},readonly",
        request.secrets_dir.display()
    )));
    assert!(args.contains(&format!(
        "type=virtiofs,source={},target={BROKER_VM_SESSION_DIR}",
        request.staging_dir.display()
    )));
    assert!(args.windows(2).any(|w| w[0] == "writd" && w[1] == "broker"));
}

#[test]
fn materialize_rejects_chatgpt_oauth_and_writes_nothing() {
    let (_host_dir, host) = host_store_with(&[("codex-pk", "PEM")]);
    let work = tempfile::tempdir().unwrap();
    let mut request = materialize_request(work.path());
    request.agent_kind = AgentKind::Codex;

    let err = materialize_broker_vm_session(
        &request,
        &chatgpt_oauth_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BrokerVmSessionError::SecretSelection(BrokerSecretSelectionError::ChatgptOauthUnsupported)
    ));
    assert!(
        !request.secrets_dir.exists(),
        "a rejected session must leave no secret store"
    );
    assert!(
        !request.staging_dir.exists(),
        "a rejected session must leave no staging material"
    );
}

#[test]
fn materialize_clears_prior_material_when_a_retry_is_rejected() {
    // A successful materialization, then a retry on the SAME dirs whose config
    // now switches the agent to chatgpt_oauth — rejected at selection, an early
    // return before any write. The prior attempt's material must not survive.
    let (_host_dir, host) = host_store_with(&[
        ("claude-pk", "PEM"),
        ("anthropic-api-key", "sk"),
        ("codex-pk", "p"),
    ]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap();
    assert!(request.staging_dir.join("config.json").exists());
    assert!(request.secrets_dir.exists());

    let mut retry = materialize_request(work.path());
    retry.agent_kind = AgentKind::Codex;
    let err = materialize_broker_vm_session(
        &retry,
        &chatgpt_oauth_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BrokerVmSessionError::SecretSelection(BrokerSecretSelectionError::ChatgptOauthUnsupported)
    ));
    // Stale config/bearer/ready marker and copied secrets from the prior run
    // must be gone — a rejected retry leaves nothing to mount.
    assert!(
        !request.staging_dir.exists(),
        "stale staging material from the prior attempt must be cleared"
    );
    assert!(
        !request.secrets_dir.exists(),
        "stale exported secrets from the prior attempt must be cleared"
    );
}

#[test]
fn materialize_fails_on_a_missing_secret_and_writes_nothing() {
    // Host store is missing claude-pk / anthropic-api-key.
    let (_host_dir, host) = host_store_with(&[]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());

    let err = materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BrokerVmSessionError::SecretExport(BrokerSecretExportError::Missing(key))
            if key == "claude-pk"
    ));
    assert!(!request.secrets_dir.exists(), "no partial secret store");
    // Secrets are exported before staging is written, so a missing key leaves
    // no staging material behind either.
    assert!(
        !request.staging_dir.exists(),
        "no staging material when secret export fails first"
    );
}

#[cfg(unix)]
#[test]
fn materialize_rolls_back_exported_secrets_when_staging_fails() {
    let (_host_dir, host) = host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    // Force the staging write to fail *after* secret export: pre-create the
    // staging path as a regular file, so writing material under it fails
    // (ENOTDIR). The export of the secret store still succeeds first.
    std::fs::write(&request.staging_dir, b"not a dir").unwrap();

    let err = materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap_err();
    assert!(matches!(err, BrokerVmSessionError::Material { .. }));
    // The ephemeral store of copied host secrets must not survive an aborted
    // launch.
    assert!(
        !request.secrets_dir.exists(),
        "exported secrets must be rolled back when staging fails"
    );
}

#[cfg(unix)]
#[test]
fn materialized_config_is_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_host_dir, host) = host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap();
    let mode = std::fs::metadata(request.staging_dir.join("config.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "broker config may carry policy and must be private"
    );
}

#[test]
fn materialize_is_safe_to_rerun_and_clears_a_stale_ready_marker() {
    let (_host_dir, host) = host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
    let work = tempfile::tempdir().unwrap();
    let request = materialize_request(work.path());
    materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap();
    // Simulate a prior broker having published readiness on the mount.
    std::fs::write(request.staging_dir.join("ready"), "18080\n").unwrap();

    materialize_broker_vm_session(
        &request,
        &materialize_host_config_json(),
        &VmHttpBearerToken::generate(),
        &host,
    )
    .unwrap();
    assert!(
        !request.staging_dir.join("ready").exists(),
        "a relaunch must clear the stale ready marker before the broker rebinds"
    );
}
