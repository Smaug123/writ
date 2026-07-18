//! Tests for daemon config parsing and validation: the `DaemonConfig` tree,
//! its `#[serde(deny_unknown_fields)]` boundaries, the `AgentVm*` sections, and
//! the explicit `validate()` checks. Split out of `config/mod.rs` (an inline
//! `#[cfg(test)]` module) to keep the config types and validators readable; the
//! tests are unchanged.

use super::*;
use crate::core::AgentKind;
use crate::github::GitHubAppRegistryConfigError;

const TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";

#[test]
fn parses_minimal_config() {
    // No `secret_store` key — the file backend at
    // `default_secret_store_path()` is the documented default.
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 42,
                "installation_id": 999,
                "installation_owner": "smaug123",
                "private_key_secret": "gh-app-pk"
            }
        },
        "policy": {
            "default_ttl": 3600,
            "writable_repos": []
        }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    let claude = &c.github_apps.agent_apps()[&AgentKind::Claude];
    assert_eq!(claude.app_id, 42);
    assert_eq!(claude.api_base, "https://api.github.com");
    assert_eq!(c.policy.default_ttl.as_i64(), 3600);
    assert!(c.agent_vm.is_none());
    assert!(c.socket_path.is_none());
    assert!(c.ui_http.is_none());
    assert!(c.run_agent.is_none());
    assert!(
        matches!(&c.secret_store, SecretStoreConfig::File { path } if *path == default_secret_store_path())
    );
}

#[test]
fn parses_ui_http_config() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "ui_http": { "bind": "127.0.0.1:7378" }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    let ui = c.ui_http.as_ref().expect("ui_http parsed");
    assert_eq!(ui.bind.to_string(), "127.0.0.1:7378");
    assert!(ui.bearer_path.is_none());
    assert_eq!(ui.bearer_path_or_default(), default_ui_http_bearer_path());
    ui.validate().expect("loopback bind validates");
}

#[test]
fn parses_ui_http_config_with_bearer_path() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "ui_http": {
            "bind": "127.0.0.1:7378",
            "bearer_path": "/tmp/writ/ui-bearer"
        }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    let ui = c.ui_http.as_ref().expect("ui_http parsed");
    assert_eq!(
        ui.bearer_path_or_default(),
        std::path::PathBuf::from("/tmp/writ/ui-bearer")
    );
}

#[test]
fn ui_http_validate_rejects_non_loopback_bind() {
    let cfg = UiHttpConfig {
        bind: "0.0.0.0:7378".parse().unwrap(),
        bearer_path: None,
    };
    let err = cfg.validate().expect_err("non-loopback rejected");
    assert!(matches!(err, UiHttpConfigError::NonLoopbackBind(_)));
}

#[test]
fn ui_http_validate_rejects_ephemeral_port() {
    let cfg = UiHttpConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        bearer_path: None,
    };
    let err = cfg.validate().expect_err("port 0 rejected");
    assert!(
        matches!(err, UiHttpConfigError::EphemeralPortBind(addr) if addr.port() == 0),
        "got: {err:?}"
    );
}

#[test]
fn ui_http_validate_accepts_ipv6_loopback() {
    let cfg = UiHttpConfig {
        bind: "[::1]:7378".parse().unwrap(),
        bearer_path: None,
    };
    cfg.validate().expect("::1 is loopback");
}

#[test]
fn ui_http_config_rejects_unknown_fields() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "ui_http": {
            "bind": "127.0.0.1:7378",
            "unknown_key": true
        }
    }"#;
    let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
    assert!(
        err.to_string().contains("unknown_key"),
        "expected unknown-field error mentioning unknown_key, got: {err}"
    );
}

#[test]
fn parses_config_with_overrides() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk",
                "api_base": "https://github.example.com/api/v3"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": ["o/n"] },
        "secret_store": { "type": "keyring" },
        "socket_path": "/tmp/test.sock",
        "audit_db": "/tmp/audit.db"
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    assert_eq!(
        c.github_apps.agent_apps()[&AgentKind::Claude].api_base,
        "https://github.example.com/api/v3"
    );
    assert_eq!(
        c.socket_path.as_deref(),
        Some(std::path::Path::new("/tmp/test.sock"))
    );
    assert!(matches!(c.secret_store, SecretStoreConfig::Keyring { service } if service == "writ"));
}

#[test]
fn parses_agent_keyed_github_apps() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "claude-pk"
            },
            "codex": {
                "app_id": 3,
                "installation_id": 4,
                "installation_owner": "o",
                "private_key_secret": "codex-pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();

    assert_eq!(
        c.github_apps.agent_apps()[&AgentKind::Claude]
            .private_key_secret
            .as_str(),
        "claude-pk"
    );
    assert_eq!(
        c.github_apps.agent_apps()[&AgentKind::Codex]
            .private_key_secret
            .as_str(),
        "codex-pk"
    );
}

#[test]
fn rejects_empty_github_apps_map() {
    let json = r#"{
        "github_apps": {},
        "policy": { "default_ttl": 600, "writable_repos": [] }
    }"#;

    let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
    assert!(
        err.to_string()
            .contains(&GitHubAppRegistryConfigError::Empty.to_string()),
        "expected Empty error, got: {err}"
    );
}

#[test]
fn rejects_legacy_github_field() {
    let json = r#"{
        "github": {
            "app_id": 1,
            "installation_id": 2,
            "installation_owner": "o",
            "private_key_secret": "pk"
        },
        "github_apps": {
            "claude": {
                "app_id": 3,
                "installation_id": 4,
                "installation_owner": "o",
                "private_key_secret": "claude-pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] }
    }"#;

    let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
    assert!(
        err.to_string().contains("github"),
        "expected unknown-field error mentioning `github`, got: {err}"
    );
}

#[test]
fn parses_agent_vm_config_and_converts_to_runtime_config() {
    let work_root = unique_config_test_path("work-root");
    let agent_run_log_root = unique_config_test_path("agent-runs");
    let git_push_staging_root = unique_config_test_path("git-push-staging");
    let mut json: serde_json::Value = serde_json::from_str(
        r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16",
                "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252,
                "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "state_dir": "/var/folders/writ/agent-vm-state",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "alpine:latest",
                "cpus": 1,
                "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0",
                "broker_port_min": 18080,
                "broker_port_max": 18081,
                "git_program": "/usr/bin/git",
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/var/folders/writ/git-work",
                "clone_timeout_secs": 30,
                "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [
                    "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE="
                ],
                "nix_cache_max_metadata_bytes": 1048576,
                "nix_cache_max_nar_bytes": 67108864,
                "claude_proxy": {
                    "upstream_base_url": "https://api.anthropic.com",
                    "auth_secret": "anthropic-api-key",
                    "auth_kind": "x_api_key",
                    "anthropic_version": "2023-06-01",
                    "timeout_secs": 60,
                    "max_request_bytes": 2097152,
                    "max_response_bytes": 8388608
                },
                "agent_run_log_root": "/var/folders/writ/agent-runs"
            }
        }
    }"#,
    )
    .unwrap();
    json["agent_vm"]["vm_http"]["work_root"] =
        serde_json::Value::String(work_root.to_string_lossy().into_owned());
    json["agent_vm"]["vm_http"]["agent_run_log_root"] =
        serde_json::Value::String(agent_run_log_root.to_string_lossy().into_owned());
    json["agent_vm"]["vm_http"]["git_push_staging_root"] =
        serde_json::Value::String(git_push_staging_root.to_string_lossy().into_owned());
    let c: DaemonConfig = serde_json::from_value(json).unwrap();
    let agent_vm = c.agent_vm.unwrap();

    let runtime = agent_vm.to_runtime_config().unwrap();

    assert_eq!(runtime.vm_http().bind_addr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(runtime.vm_http().broker_port_range().min().get(), 18080);
    assert_eq!(runtime.vm_http().broker_port_range().max().get(), 18081);
    assert_eq!(runtime.vm_http().git_clone().work_root(), work_root);
    assert_eq!(
        runtime.vm_http().nix_cache().upstream_base_url().as_str(),
        "https://cache.nixos.org/"
    );
    assert_eq!(
        runtime.vm_http().nix_cache().max_metadata_bytes(),
        1_048_576
    );
    assert_eq!(runtime.vm_http().nix_cache().max_nar_bytes(), 67_108_864);
    // Omitted from JSON, so the local flake-input cache defaults under
    // work_root and is the sole local cache dir wired into the nix-cache
    // config (no pre-warm dir configured).
    assert_eq!(
        runtime.vm_http().nix_cache().local_cache_dirs(),
        [work_root.join("flake-input-cache")],
    );
    assert_eq!(
        runtime
            .vm_http()
            .nix_cache()
            .trusted_public_keys()
            .nix_conf_value(),
        TEST_NIX_CACHE_PUBLIC_KEY
    );
    let claude_proxy = runtime.vm_http().claude_proxy().unwrap();
    assert_eq!(
        claude_proxy.upstream_base_url().as_str(),
        "https://api.anthropic.com/"
    );
    assert_eq!(claude_proxy.auth_secret().as_str(), "anthropic-api-key");
    assert_eq!(claude_proxy.auth_kind(), VmHttpClaudeProxyAuthKind::XApiKey);
    assert_eq!(
        claude_proxy.anthropic_version().to_str().unwrap(),
        "2023-06-01"
    );
    assert_eq!(claude_proxy.max_request_bytes(), 2_097_152);
    assert_eq!(claude_proxy.max_response_bytes(), 8_388_608);
    assert_eq!(runtime.vm_http().agent_run_log_root(), agent_run_log_root);
    assert_eq!(
        runtime.vm_http().git_push_staging_root(),
        git_push_staging_root
    );
    assert_eq!(
        runtime.vm_http().git_push_body_limits(),
        VmGitPushBodyLimits::new(
            default_git_push_max_body_bytes(),
            default_git_push_max_metadata_bytes(),
            default_git_push_max_bundle_bytes(),
        )
        .unwrap()
    );
    assert_eq!(runtime.lifecycle().subnet_index_min(), 252);
    assert_eq!(runtime.lifecycle().subnet_index_max(), 253);
}

#[test]
fn parses_agent_vm_config_with_oauth_claude_proxy_auth_kind() {
    let work_root = unique_config_test_path("work-root");
    let agent_run_log_root = unique_config_test_path("agent-runs");
    let mut json: serde_json::Value = serde_json::from_str(
        r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "agent_vm": {
            "lifecycle": {
                "ipv4_pool": "192.168.0.0/16",
                "ipv6_pool": "fd83:b6f2:e57::/48",
                "subnet_index_min": 252,
                "subnet_index_max": 253,
                "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                "state_dir": "/var/folders/writ/agent-vm-state",
                "ipv6_mode": "ipv4_only_no_guest_ipv6",
                "image": "alpine:latest",
                "cpus": 1,
                "memory_mib": 512
            },
            "vm_http": {
                "bind_addr": "0.0.0.0",
                "broker_port_min": 18080,
                "broker_port_max": 18081,
                "git_program": "/usr/bin/git",
                "git_clone_base_url": "https://github.com",
                "askpass_program": "/usr/local/libexec/writ-git-askpass",
                "work_root": "/var/folders/writ/git-work",
                "clone_timeout_secs": 30,
                "max_bundle_bytes": 1048576,
                "nix_cache_url": "https://cache.nixos.org",
                "nix_cache_trusted_public_keys": [],
                "nix_cache_max_metadata_bytes": 1048576,
                "nix_cache_max_nar_bytes": 67108864,
                "claude_proxy": {
                    "upstream_base_url": "https://api.anthropic.com",
                    "auth_secret": "anthropic-oauth-token",
                    "auth_kind": "oauth",
                    "anthropic_version": "2023-06-01",
                    "timeout_secs": 60,
                    "max_request_bytes": 2097152,
                    "max_response_bytes": 8388608
                },
                "agent_run_log_root": "/var/folders/writ/agent-runs"
            }
        }
    }"#,
    )
    .unwrap();
    json["agent_vm"]["vm_http"]["work_root"] =
        serde_json::Value::String(work_root.to_string_lossy().into_owned());
    json["agent_vm"]["vm_http"]["agent_run_log_root"] =
        serde_json::Value::String(agent_run_log_root.to_string_lossy().into_owned());
    let c: DaemonConfig = serde_json::from_value(json).unwrap();
    let agent_vm = c.agent_vm.unwrap();

    let runtime = agent_vm.to_runtime_config().unwrap();
    let claude_proxy = runtime.vm_http().claude_proxy().unwrap();
    assert_eq!(claude_proxy.auth_secret().as_str(), "anthropic-oauth-token");
    assert_eq!(claude_proxy.auth_kind(), VmHttpClaudeProxyAuthKind::OAuth);
}

fn unique_config_test_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "writ-config-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn valid_agent_vm_http_config() -> AgentVmHttpConfig {
    let work_root = unique_config_test_path("work-root");
    AgentVmHttpConfig {
        bind_addr: Ipv4Addr::UNSPECIFIED,
        broker_port_min: 18080,
        broker_port_max: 18081,
        git_program: PathBuf::from("/usr/bin/git"),
        nix_program: PathBuf::from("/usr/bin/nix"),
        git_clone_base_url: DEFAULT_GIT_CLONE_BASE_URL.into(),
        askpass_program: PathBuf::from("/usr/local/libexec/writ-git-askpass"),
        token_env: "WRIT_GIT_TOKEN".into(),
        work_root,
        clone_timeout_secs: 30,
        max_bundle_bytes: 1_048_576,
        nix_cache_url: "https://cache.nixos.org".into(),
        nix_cache_trusted_public_keys: Vec::new(),
        nix_cache_max_metadata_bytes: 1_048_576,
        nix_cache_max_nar_bytes: 67_108_864,
        flake_input_cache_dir: None,
        nix_prewarm_cache_dir: None,
        flake_mirror_cache_dir: None,
        flake_mirror_cache_max_entries: default_flake_mirror_cache_max_entries(),
        flake_mirror_cache_max_bytes: default_flake_mirror_cache_max_bytes(),
        flake_materialize_scratch_dir: None,
        flake_provision_max_input_count: default_flake_provision_max_input_count(),
        flake_provision_max_total_bytes: default_flake_provision_max_total_bytes(),
        flake_provision_timeout_secs: default_flake_provision_timeout_secs(),
        claude_proxy: None,
        openai_proxy: None,
        agent_run_log_root: None,
        git_push_staging_root: None,
        git_push_max_body_bytes: default_git_push_max_body_bytes(),
        git_push_max_metadata_bytes: default_git_push_max_metadata_bytes(),
        git_push_max_bundle_bytes: default_git_push_max_bundle_bytes(),
    }
}

fn valid_agent_vm_lifecycle_config() -> AgentVmLifecycleConfig {
    AgentVmLifecycleConfig {
        ipv4_pool: "192.168.0.0/16".into(),
        ipv6_pool: "fd83:b6f2:e57::/48".into(),
        subnet_index_min: 252,
        subnet_index_max: 253,
        container: PathBuf::from("container"),
        sudo: PathBuf::from("sudo"),
        pf_helper: PathBuf::from("/usr/local/libexec/writ-agent-vm-pf-helper"),
        state_dir: Some(PathBuf::from("/var/folders/writ/agent-vm-state")),
        ipv6_mode: Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        broker_placement: BrokerPlacement::Host,
        image: "alpine:latest".into(),
        broker_image: None,
        cpus: 1,
        memory_mib: 512,
    }
}

fn agent_vm_lifecycle_json(broker_placement_field: &str) -> String {
    format!(
        r#"{{
            "ipv4_pool": "192.168.0.0/16",
            "ipv6_pool": "fd83:b6f2:e57::/48",
            "subnet_index_min": 252,
            "subnet_index_max": 252,
            "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
            "state_dir": "/tmp/writ-test-broker-placement-state",
            "ipv6_mode": "ipv4_only_no_guest_ipv6",
            {broker_placement_field}
            "image": "alpine:latest",
            "cpus": 1,
            "memory_mib": 512
        }}"#
    )
}

#[test]
fn broker_placement_defaults_to_host_when_absent() {
    let cfg: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json("")).unwrap();
    assert_eq!(cfg.broker_placement, BrokerPlacement::Host);
    let runtime = cfg.to_runtime_config().unwrap();
    assert_eq!(runtime.broker_placement(), BrokerPlacement::Host);
}

#[test]
fn broker_placement_vm_parses_and_threads_to_runtime() {
    let cfg: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json(
        r#""broker_placement": "vm", "broker_image": "writ-broker-vm:latest","#,
    ))
    .unwrap();
    assert_eq!(cfg.broker_placement, BrokerPlacement::Vm);
    let runtime = cfg.to_runtime_config().unwrap();
    assert_eq!(runtime.broker_placement(), BrokerPlacement::Vm);
    assert_eq!(
        runtime.broker_image().map(ContainerImage::as_str),
        Some("writ-broker-vm:latest")
    );
}

#[test]
fn broker_placement_vm_without_broker_image_is_rejected() {
    let cfg: AgentVmLifecycleConfig =
        serde_json::from_str(&agent_vm_lifecycle_json(r#""broker_placement": "vm","#)).unwrap();
    assert!(matches!(
        cfg.to_runtime_config(),
        Err(AgentVmDaemonConfigError::LifecycleRuntime(
            AgentVmLifecycleRuntimeConfigError::BrokerImageRequiredForVmPlacement
        ))
    ));
}

#[test]
fn host_placement_leaves_broker_image_unset() {
    let cfg: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json("")).unwrap();
    let runtime = cfg.to_runtime_config().unwrap();
    assert!(runtime.broker_image().is_none());
}

#[test]
fn host_placement_ignores_a_set_broker_image() {
    // broker_image is documented as ignored for the host broker: even an
    // empty/garbage value must not reject startup, and broker_image() stays
    // None so the "Some iff vm" invariant holds.
    let cfg: AgentVmLifecycleConfig =
        serde_json::from_str(&agent_vm_lifecycle_json(r#""broker_image": "","#)).unwrap();
    assert_eq!(cfg.broker_placement, BrokerPlacement::Host);
    let runtime = cfg.to_runtime_config().unwrap();
    assert!(runtime.broker_image().is_none());
}

#[test]
fn broker_vm_host_facts_attach_only_for_vm_placement() {
    let vm: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json(
        r#""broker_placement": "vm", "broker_image": "writ-broker-vm:latest","#,
    ))
    .unwrap();
    let runtime = vm
        .to_runtime_config()
        .unwrap()
        .with_broker_vm_host_facts("{\"raw\":true}", std::path::Path::new("/var/lib/writ/a.db"));
    assert_eq!(runtime.host_config_json(), Some("{\"raw\":true}"));
    assert_eq!(
        runtime.host_audit_db(),
        Some(std::path::Path::new("/var/lib/writ/a.db"))
    );
}

#[test]
fn host_placement_ignores_broker_vm_host_facts() {
    // writd calls the builder unconditionally; host placement must retain
    // nothing, keeping the "Some iff vm" invariant.
    let host: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json("")).unwrap();
    let runtime = host
        .to_runtime_config()
        .unwrap()
        .with_broker_vm_host_facts("{\"raw\":true}", std::path::Path::new("/var/lib/writ/a.db"));
    assert!(runtime.host_config_json().is_none());
    assert!(runtime.host_audit_db().is_none());
}

#[test]
fn broker_vm_host_facts_are_none_until_the_builder_runs() {
    // Even a vm config carries no host facts until writd attaches them.
    let vm: AgentVmLifecycleConfig = serde_json::from_str(&agent_vm_lifecycle_json(
        r#""broker_placement": "vm", "broker_image": "writ-broker-vm:latest","#,
    ))
    .unwrap();
    let runtime = vm.to_runtime_config().unwrap();
    assert!(runtime.host_config_json().is_none());
    assert!(runtime.host_audit_db().is_none());
}

#[test]
fn broker_placement_rejects_unknown_value() {
    let err = serde_json::from_str::<AgentVmLifecycleConfig>(&agent_vm_lifecycle_json(
        r#""broker_placement": "elsewhere","#,
    ));
    assert!(err.is_err(), "unknown broker_placement should be rejected");
}

#[test]
fn agent_vm_config_rejects_non_wildcard_vm_http_bind_address() {
    let mut vm_http = valid_agent_vm_http_config();
    vm_http.bind_addr = Ipv4Addr::LOCALHOST;
    let c = AgentVmDaemonConfig {
        lifecycle: valid_agent_vm_lifecycle_config(),
        vm_http,
    };

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmDaemonConfigError::Runtime(
            AgentVmDaemonRuntimeConfigError::NonWildcardVmHttpBindAddr(addr)
        )) if addr == Ipv4Addr::LOCALHOST
    ));
}

#[test]
fn agent_vm_http_config_rejects_privileged_broker_port() {
    let mut c = valid_agent_vm_http_config();
    c.broker_port_min = 80;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::BrokerPortRange(
            AgentVmConfigError::PrivilegedBrokerPort(80)
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_empty_broker_port_range() {
    let mut c = valid_agent_vm_http_config();
    c.broker_port_min = 18081;
    c.broker_port_max = 18080;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::BrokerPortRange(
            AgentVmConfigError::EmptyBrokerPortRange {
                min: 18081,
                max: 18080
            }
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_invalid_token_env() {
    let mut c = valid_agent_vm_http_config();
    c.token_env = "bad-name".into();

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::TokenEnv(
            GitSecretEnvVarError::InvalidByte(raw)
        )) if raw == "bad-name"
    ));
}

#[test]
fn agent_vm_http_config_rejects_empty_git_program() {
    let mut c = valid_agent_vm_http_config();
    c.git_program = PathBuf::new();

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::EmptyPath {
                field: "git_program"
            }
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_unsafe_git_clone_base_url() {
    let mut c = valid_agent_vm_http_config();
    c.git_clone_base_url = "ssh://github.com".into();

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::UnsupportedGitCloneBaseUrlScheme { scheme, .. }
        )) if scheme == "ssh"
    ));

    c.git_clone_base_url = "https://user:token@github.com".into();
    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::GitCloneBaseUrlHasCredentials(_)
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_relative_askpass_program() {
    let mut c = valid_agent_vm_http_config();
    c.askpass_program = PathBuf::from("askpass");

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::RelativePath {
                field: "askpass_program",
                path
            }
        )) if path.as_os_str() == "askpass"
    ));
}

#[test]
fn agent_vm_http_config_rejects_relative_work_root() {
    let mut c = valid_agent_vm_http_config();
    c.work_root = PathBuf::from("relative");

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::RelativePath {
                field: "work_root",
                path
            }
        )) if path.as_os_str() == "relative"
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_clone_timeout() {
    let mut c = valid_agent_vm_http_config();
    c.clone_timeout_secs = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::ZeroTimeout
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_max_bundle_bytes() {
    let mut c = valid_agent_vm_http_config();
    c.max_bundle_bytes = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitClone(
            GitCloneBundlePlanError::ZeroMaxBundleBytes
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_invalid_nix_cache_url() {
    let mut c = valid_agent_vm_http_config();
    c.nix_cache_url = "file:///nix/cache".into();

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::NixCache(
            VmHttpNixCacheConfigError::UnsupportedUpstreamScheme { .. }
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_nix_cache_metadata_limit() {
    let mut c = valid_agent_vm_http_config();
    c.nix_cache_max_metadata_bytes = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::NixCache(
            VmHttpNixCacheConfigError::EmptyMaxMetadataBytes
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_nix_cache_nar_limit() {
    let mut c = valid_agent_vm_http_config();
    c.nix_cache_max_nar_bytes = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::NixCache(
            VmHttpNixCacheConfigError::EmptyMaxNarBytes
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_invalid_nix_cache_trusted_public_key() {
    let mut c = valid_agent_vm_http_config();
    c.nix_cache_trusted_public_keys = vec![format!(
        "cache key:{}",
        TEST_NIX_CACHE_PUBLIC_KEY.split_once(':').unwrap().1
    )];

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::NixTrustedPublicKeys(err))
            if err.index() == 0 && err.raw().starts_with("cache key:")
    ));
}

#[test]
fn agent_vm_http_config_rejects_invalid_claude_proxy_url() {
    let mut c = valid_agent_vm_http_config();
    c.claude_proxy = Some(AgentVmHttpClaudeProxyConfig {
        upstream_base_url: "file:///api".into(),
        auth_secret: SecretKey::new("anthropic-api-key").unwrap(),
        auth_kind: VmHttpClaudeProxyAuthKind::XApiKey,
        anthropic_version: DEFAULT_CLAUDE_ANTHROPIC_VERSION.into(),
        timeout_secs: 60,
        max_request_bytes: 1_048_576,
        max_response_bytes: 8_388_608,
    });

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::ClaudeProxy(
            VmHttpClaudeProxyConfigError::UnsupportedUpstreamScheme { .. }
        ))
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_claude_proxy_request_limit() {
    let mut c = valid_agent_vm_http_config();
    c.claude_proxy = Some(AgentVmHttpClaudeProxyConfig {
        upstream_base_url: "https://api.anthropic.com".into(),
        auth_secret: SecretKey::new("anthropic-api-key").unwrap(),
        auth_kind: VmHttpClaudeProxyAuthKind::XApiKey,
        anthropic_version: DEFAULT_CLAUDE_ANTHROPIC_VERSION.into(),
        timeout_secs: 60,
        max_request_bytes: 0,
        max_response_bytes: 8_388_608,
    });

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::ClaudeProxy(
            VmHttpClaudeProxyConfigError::EmptyMaxRequestBytes
        ))
    ));
}

/// Every field that has a `serde(default = ...)` should produce its
/// documented value when omitted from the JSON. The minimal config below
/// supplies only the three fields without defaults (`broker_port_*`,
/// `askpass_program`); everything else must come from the default fns.
#[test]
fn agent_vm_http_config_applies_defaults_for_omitted_fields() {
    let json = r#"{
        "broker_port_min": 18080,
        "broker_port_max": 18081,
        "askpass_program": "/usr/local/libexec/writ-git-askpass"
    }"#;
    let c: AgentVmHttpConfig = serde_json::from_str(json).unwrap();
    assert_eq!(c.bind_addr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(c.git_program, PathBuf::from("git"));
    assert_eq!(c.git_clone_base_url, DEFAULT_GIT_CLONE_BASE_URL);
    assert_eq!(c.token_env, "WRIT_GIT_TOKEN");
    assert_eq!(c.work_root, default_vm_http_work_root());
    assert_eq!(c.clone_timeout_secs, 300);
    assert_eq!(c.max_bundle_bytes, 64 * 1024 * 1024);
    assert_eq!(c.nix_cache_url, "https://cache.nixos.org");
    assert_eq!(
        c.nix_cache_trusted_public_keys,
        vec!["cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=".to_string()]
    );
    assert_eq!(c.nix_cache_max_metadata_bytes, 1024 * 1024);
    assert_eq!(c.nix_cache_max_nar_bytes, 512 * 1024 * 1024);
    assert!(c.claude_proxy.is_none());
    assert!(c.openai_proxy.is_none());
    assert!(c.agent_run_log_root.is_none());
    assert!(c.git_push_staging_root.is_none());
    assert!(c.flake_input_cache_dir.is_none());
    assert!(c.flake_mirror_cache_dir.is_none());
}

#[test]
fn agent_vm_http_config_rejects_relative_agent_run_log_root() {
    let mut c = valid_agent_vm_http_config();
    c.agent_run_log_root = Some(PathBuf::from("agent-runs"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeAgentRunLogRoot(path))
            if path.as_os_str() == "agent-runs"
    ));
}

#[test]
fn agent_vm_http_config_rejects_unwritable_agent_run_log_root() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("not-a-directory");
    std::fs::write(&path, b"file").unwrap();
    let mut c = valid_agent_vm_http_config();
    c.agent_run_log_root = Some(path.clone());

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::AgentRunLogRootCreate {
            path: failed,
            ..
        }) if failed == path
    ));
}

/// A typo on a top-level field (e.g. `agentVm` instead of `agent_vm`)
/// would otherwise be silently ignored — `agent_vm` then falls back to
/// its `Option<…>` default and the daemon starts without VM HTTP setup.
/// `deny_unknown_fields` forces a hard failure at config load time.
#[test]
fn daemon_config_rejects_unknown_top_level_field() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "agentVm": { "lifecycle": {}, "vm_http": {} }
    }"#;
    let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
    assert!(
        err.to_string().contains("agentVm"),
        "error should mention the unknown field, got: {err}"
    );
}

#[test]
fn agent_vm_http_config_rejects_relative_git_push_staging_root() {
    let mut c = valid_agent_vm_http_config();
    c.git_push_staging_root = Some(PathBuf::from("git-push-staging"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeGitPushStagingRoot(path))
            if path.as_os_str() == "git-push-staging"
    ));
}

#[test]
fn agent_vm_http_config_rejects_unwritable_git_push_staging_root() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("not-a-directory");
    std::fs::write(&path, b"file").unwrap();
    let mut c = valid_agent_vm_http_config();
    c.git_push_staging_root = Some(path.clone());

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitPushStagingRootCreate {
            path: failed,
            ..
        }) if failed == path
    ));
}

#[test]
fn agent_vm_http_config_wires_explicit_flake_input_cache_dir() {
    let flake_cache = unique_config_test_path("flake-input-cache");
    let mut c = valid_agent_vm_http_config();
    c.flake_input_cache_dir = Some(flake_cache.clone());

    let runtime = c.to_runtime_config().unwrap();

    assert_eq!(
        runtime.nix_cache().local_cache_dirs(),
        std::slice::from_ref(&flake_cache),
    );
}

#[test]
fn agent_vm_http_config_rejects_relative_flake_input_cache_dir() {
    let mut c = valid_agent_vm_http_config();
    c.flake_input_cache_dir = Some(PathBuf::from("flake-input-cache"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeFlakeInputCacheDir(path))
            if path.as_os_str() == "flake-input-cache"
    ));
}

#[test]
fn agent_vm_http_config_wires_prewarm_cache_dir_first() {
    let prewarm = unique_config_test_path("nix-prewarm-cache");
    let flake_cache = unique_config_test_path("flake-input-cache");
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(prewarm.clone());
    c.flake_input_cache_dir = Some(flake_cache.clone());

    let runtime = c.to_runtime_config().unwrap();

    // Served local-first in order: the durable pre-warm dir ahead of the
    // auto-provisioned flake-input dir.
    assert_eq!(
        runtime.nix_cache().local_cache_dirs(),
        [prewarm.clone(), flake_cache.clone()],
    );
    // The role is recorded on the runtime config so the daemon can tell a
    // pre-warming deployment apart (it gates the strict warm substituter).
    assert_eq!(runtime.nix_prewarm_cache_dir(), Some(prewarm.as_path()));
}

#[test]
fn agent_vm_http_config_records_no_prewarm_role_when_unconfigured() {
    let runtime = valid_agent_vm_http_config().to_runtime_config().unwrap();

    assert_eq!(runtime.nix_prewarm_cache_dir(), None);
}

#[test]
fn agent_vm_http_config_tolerates_a_missing_prewarm_cache_dir() {
    // Unlike the flake-input cache, the broker only reads the pre-warm dir
    // (an egress builder writes it out of band), so config must NOT create or
    // probe it: a not-yet-populated path is accepted and left untouched.
    let prewarm = unique_config_test_path("nix-prewarm-cache-absent");
    assert!(!prewarm.exists());
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(prewarm.clone());

    let runtime = c.to_runtime_config().unwrap();

    assert_eq!(
        runtime.nix_cache().local_cache_dirs().first(),
        Some(&prewarm)
    );
    assert!(
        !prewarm.exists(),
        "config must not create the read-only pre-warm dir",
    );
}

#[test]
fn agent_vm_http_config_rejects_relative_prewarm_cache_dir() {
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(PathBuf::from("nix-prewarm-cache"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeNixPrewarmCacheDir(path))
            if path.as_os_str() == "nix-prewarm-cache"
    ));
}

#[test]
fn agent_vm_http_config_rejects_prewarm_cache_dir_that_is_not_a_directory() {
    // A typo pointing the (read-only, never-created) pre-warm dir at a file
    // must fail fast: otherwise every narinfo lookup would hit an I/O error
    // and fail closed before the flake-input cache or upstream is tried.
    let not_a_dir = unique_config_test_path("nix-prewarm-not-a-dir");
    std::fs::write(&not_a_dir, b"oops").unwrap();
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(not_a_dir.clone());

    let result = c.to_runtime_config();
    std::fs::remove_file(&not_a_dir).ok();

    assert!(matches!(
        result,
        Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
            if path == not_a_dir
    ));
}

#[cfg(unix)]
#[test]
fn agent_vm_http_config_rejects_non_searchable_prewarm_cache_dir() {
    use std::os::unix::fs::PermissionsExt as _;
    // Root bypasses the directory search bit, so the invariant is only
    // observable as a non-root user — which is how the broker runs. Skip
    // under root rather than assert a rejection that cannot happen there.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    // A dir that is listable (r) but not searchable (no x): `read_dir` would
    // succeed, yet every `<dir>/<hash>.narinfo` open would 502. The
    // child-stat probe must reject it.
    let dir = unique_config_test_path("nix-prewarm-no-search");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o400)).unwrap();
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(dir.clone());

    let result = c.to_runtime_config();
    // Restore searchable perms so cleanup can remove the dir.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    std::fs::remove_dir(&dir).ok();

    assert!(matches!(
        result,
        Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
            if path == dir
    ));
}

#[cfg(unix)]
#[test]
fn agent_vm_http_config_rejects_non_readable_prewarm_cache_dir() {
    use std::os::unix::fs::PermissionsExt as _;
    // Root bypasses the read bit too; skip there (the broker runs non-root).
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    // A dir that is searchable (x) but not listable (no r): children open by
    // name, but `local_cache_has_narinfo`'s `read_dir` would hit EACCES,
    // making a pre-warm-only no-egress guest proxy cache-info to an
    // unreachable upstream. Require listability too.
    let dir = unique_config_test_path("nix-prewarm-no-read");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o100)).unwrap();
    let mut c = valid_agent_vm_http_config();
    c.nix_prewarm_cache_dir = Some(dir.clone());

    let result = c.to_runtime_config();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    std::fs::remove_dir(&dir).ok();

    assert!(matches!(
        result,
        Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
            if path == dir
    ));
}

#[test]
fn agent_vm_http_config_wires_explicit_flake_mirror_cache_dir() {
    let mirror_cache = unique_config_test_path("flake-mirror-cache");
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(mirror_cache.clone());

    let runtime = c.to_runtime_config().unwrap();

    assert_eq!(
        runtime.git_clone().mirror_cache().map(|cache| cache.root()),
        Some(mirror_cache.as_path())
    );
}

#[test]
fn agent_vm_http_config_defaults_to_no_mirror_cache() {
    let runtime = valid_agent_vm_http_config().to_runtime_config().unwrap();
    // Retention is opt-in: without the dir, the clone handler discards the
    // mirror exactly as before, and there is nothing to bound.
    assert!(runtime.git_clone().mirror_cache().is_none());
    assert!(runtime.git_clone().mirror_gc_bounds().is_none());
}

#[test]
fn agent_vm_http_config_pairs_gc_bounds_with_the_mirror_cache() {
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
    c.flake_mirror_cache_max_entries = 7;
    c.flake_mirror_cache_max_bytes = 4096;

    let runtime = c.to_runtime_config().unwrap();

    // Eviction bounds are wired exactly when the cache they bound exists.
    assert_eq!(
        runtime.git_clone().mirror_gc_bounds(),
        Some(crate::vm_git_mirror_cache::MirrorCacheBounds::new(7, 4096))
    );
}

#[test]
fn agent_vm_http_config_rejects_relative_flake_mirror_cache_dir() {
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(PathBuf::from("flake-mirror-cache"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeFlakeMirrorCacheDir(path))
            if path.as_os_str() == "flake-mirror-cache"
    ));
}

#[test]
fn agent_vm_http_config_enables_flake_provision_with_the_mirror_cache() {
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));

    let runtime = c.to_runtime_config().unwrap();

    // Provisioning re-derives a checkout from the retained mirror, so it is
    // enabled exactly when the mirror cache is configured.
    assert!(runtime.flake_provision().is_some());
}

#[test]
fn agent_vm_http_config_disables_flake_provision_without_the_mirror_cache() {
    let runtime = valid_agent_vm_http_config().to_runtime_config().unwrap();
    // With nothing to provision from, the endpoint stays disabled even
    // though the flake-input cache is always wired for serving.
    assert!(runtime.flake_provision().is_none());
}

#[test]
fn agent_vm_http_config_rejects_relative_flake_materialize_scratch_dir() {
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
    c.flake_materialize_scratch_dir = Some(PathBuf::from("flake-materialize"));

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::RelativeFlakeMaterializeScratchDir(path))
            if path.as_os_str() == "flake-materialize"
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_flake_provision_input_bound() {
    let mut c = valid_agent_vm_http_config();
    c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
    c.flake_provision_max_input_count = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::FlakeProvisionBounds(_))
    ));
}

#[test]
fn agent_vm_http_config_rejects_unwritable_flake_input_cache_dir() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("not-a-directory");
    std::fs::write(&path, b"file").unwrap();
    let mut c = valid_agent_vm_http_config();
    c.flake_input_cache_dir = Some(path.clone());

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::FlakeInputCacheDirCreate {
            path: failed,
            ..
        }) if failed == path
    ));
}

#[test]
fn agent_vm_http_config_rejects_zero_git_push_body_limit() {
    let mut c = valid_agent_vm_http_config();
    c.git_push_max_metadata_bytes = 0;

    assert!(matches!(
        c.to_runtime_config(),
        Err(AgentVmHttpConfigError::GitPushBodyLimits(
            VmGitPushBodyLimitsError::EmptyMaxMetadataBytes
        ))
    ));
}

/// `to_runtime_config` must leave the work root at 0700, because the
/// guest-side `prepare_git_work_root` rejects any group/world bits and a
/// fresh install relies on the daemon — not the user — to create the
/// default work root.
#[test]
fn agent_vm_http_config_creates_work_root_at_mode_0700() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    // Pick a path that does not yet exist so `to_runtime_config` is the
    // one that creates the directory.
    let work_root = temp.path().join("fresh-vm-work");
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();

    c.to_runtime_config().expect("runtime config builds");

    let mode = std::fs::symlink_metadata(&work_root)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "work_root {} should be private (0700), got {:04o}",
        work_root.display(),
        mode & 0o777
    );
}

/// A pre-existing work_root with group/world bits must fail startup, not
/// silently boot a daemon whose clone route is unusable.
#[test]
fn agent_vm_http_config_rejects_existing_work_root_with_loose_perms() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let work_root = temp.path().join("loose-vm-work");
    std::fs::create_dir(&work_root).unwrap();
    std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();

    let err = c.to_runtime_config().expect_err("loose perms rejected");
    assert!(
        matches!(
            err,
            AgentVmHttpConfigError::WorkRootInsecure { ref path, mode }
                if *path == work_root && mode == 0o755
        ),
        "expected WorkRootInsecure, got {err:?}"
    );
}

#[test]
fn agent_vm_http_config_accepts_existing_work_root_at_mode_0700() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let work_root = temp.path().join("strict-vm-work");
    std::fs::create_dir(&work_root).unwrap();
    std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();

    c.to_runtime_config()
        .expect("pre-existing 0700 work_root accepted");

    let mode = std::fs::symlink_metadata(&work_root)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn agent_vm_http_config_rejects_work_root_that_is_a_file() {
    let temp = tempfile::tempdir().unwrap();
    let work_root = temp.path().join("not-a-dir");
    std::fs::write(&work_root, b"file").unwrap();
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();

    let err = c.to_runtime_config().expect_err("non-directory rejected");
    assert!(
        matches!(
            err,
            AgentVmHttpConfigError::WorkRootNotDirectory { ref path } if *path == work_root
        ),
        "expected WorkRootNotDirectory, got {err:?}"
    );
}

#[test]
fn agent_vm_http_config_defaults_git_push_staging_root_to_work_root_subdir() {
    // Use a non-existent subpath so `ensure_vm_http_work_root_private`
    // creates the work root at 0700 (the failure mode it exists to
    // prevent). Passing `temp.path()` directly would hand the validator a
    // 0755 dir on systems where `tempfile` honours the default umask.
    let temp = tempfile::tempdir().unwrap();
    let work_root = temp.path().join("vm-work");
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();
    c.git_push_staging_root = None;

    let runtime = c.to_runtime_config().unwrap();

    assert_eq!(
        runtime.git_push_staging_root(),
        work_root.join("git-push-staging")
    );
}

#[test]
fn agent_vm_http_config_defaults_flake_input_cache_dir_to_work_root_subdir() {
    let temp = tempfile::tempdir().unwrap();
    let work_root = temp.path().join("vm-work");
    let mut c = valid_agent_vm_http_config();
    c.work_root = work_root.clone();
    c.flake_input_cache_dir = None;

    let runtime = c.to_runtime_config().unwrap();

    assert_eq!(
        runtime.nix_cache().local_cache_dirs(),
        [work_root.join("flake-input-cache")],
    );
}

#[test]
fn rejects_invalid_secret_key_name_in_config() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "bad/key"
            }
        },
        "policy": { "default_ttl": 300 },
        "secret_store": { "type": "file", "path": "/tmp" }
    }"#;
    assert!(serde_json::from_str::<DaemonConfig>(json).is_err());
}

/// `run_agent` is optional: an absent section parses cleanly and
/// the daemon will refuse RunAgent at request time.
#[test]
fn parses_config_without_run_agent_section() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    assert!(c.run_agent.is_none());
}

/// `run_agent` minimal shape: only `spawn_command` is required;
/// `notes_repo_path`, `signing_key_secret`, and `spawn_args`
/// default. The accessors return the documented defaults.
#[test]
fn parses_run_agent_section_with_defaults() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "run_agent": { "spawn_command": "/usr/bin/claude" }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    let cfg = c.run_agent.expect("run_agent parsed");
    assert_eq!(cfg.spawn_command, PathBuf::from("/usr/bin/claude"));
    assert!(cfg.spawn_args.is_empty());
    assert!(cfg.notes_repo_path.is_none());
    assert!(cfg.signing_key_secret.is_none());
    assert_eq!(cfg.notes_repo_path_or_default(), default_notes_repo_path());
    assert_eq!(
        cfg.signing_key_secret_or_default().as_str(),
        DEFAULT_WRIT_SIGNING_KEY_SECRET
    );
}

/// `run_agent` with every field overridden — pins the field names
/// on the wire so a config-file rename is a visible breaking
/// change.
#[test]
fn parses_run_agent_section_with_all_fields() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "run_agent": {
            "spawn_command": "/opt/agents/claude",
            "spawn_args": ["--headless", "--no-color"],
            "notes_repo_path": "/var/lib/writ/notes",
            "signing_key_secret": "custom-signing"
        }
    }"#;
    let c: DaemonConfig = serde_json::from_str(json).unwrap();
    let cfg = c.run_agent.expect("run_agent parsed");
    assert_eq!(cfg.spawn_command, PathBuf::from("/opt/agents/claude"));
    assert_eq!(cfg.spawn_args, vec!["--headless", "--no-color"]);
    assert_eq!(
        cfg.notes_repo_path_or_default(),
        PathBuf::from("/var/lib/writ/notes")
    );
    assert_eq!(
        cfg.signing_key_secret_or_default().as_str(),
        "custom-signing"
    );
}

/// `deny_unknown_fields` on `RunAgentDaemonConfig` keeps the
/// config schema honest: a typo'd key name is rejected at parse
/// time, not silently dropped.
#[test]
fn run_agent_section_rejects_unknown_fields() {
    let json = r#"{
        "github_apps": {
            "claude": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            }
        },
        "policy": { "default_ttl": 600, "writable_repos": [] },
        "run_agent": {
            "spawn_command": "/bin/true",
            "spwan_args": []
        }
    }"#;
    let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
    assert!(err.to_string().contains("spwan_args"));
}

/// `materialize` is idempotent across boots: the first call
/// generates and persists a fresh signing key (and creates the
/// bare notes repo on disk); the second call loads the same key
/// and reuses the same repo. This is the boot-time invariant
/// writd relies on.
#[test]
fn materialize_persists_signing_key_and_initialises_notes_repo() {
    use crate::secret::{SecretError, SecretStore};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct InMem(Mutex<HashMap<String, String>>);
    impl SecretStore for InMem {
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

    let tmp = tempfile::tempdir().unwrap();
    let cfg = RunAgentDaemonConfig {
        notes_repo_path: Some(tmp.path().join("notes-repo")),
        signing_key_secret: Some(SecretKey::new("writ-signing-key").unwrap()),
        spawn_command: PathBuf::from("/bin/cat"),
        spawn_args: vec![],
    };
    let store = InMem::default();

    let first = cfg.materialize(&store).unwrap();
    assert!(
        first.signing.was_generated(),
        "first boot generates the key"
    );
    let fp = first.signing.signing_key().fingerprint();
    assert!(first.notes_repo.path().exists());
    assert_eq!(first.spawn.command, PathBuf::from("/bin/cat"));

    let second = cfg.materialize(&store).unwrap();
    assert!(
        !second.signing.was_generated(),
        "second boot loads the existing key"
    );
    assert_eq!(
        second.signing.signing_key().fingerprint(),
        fp,
        "fingerprint is stable across boots — same key material",
    );
}
