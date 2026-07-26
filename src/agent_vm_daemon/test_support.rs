//! Shared fixtures for the `agent_vm_daemon` test modules: the in-memory
//! secret store and broker state, the fake `container`/`pf-helper` tools
//! the lifecycle drives, and the daemon-config constructors.
//!
//! Hoisted here so the per-concern `*_tests` modules and the inline `spec`
//! reuse one set of constructors. `super::*` re-exports the production
//! items and the parent's private `crate::*` imports; the explicit `use`s
//! below cover the test-only constructors these helpers call.
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;

use crate::audit::AuditLog;
use crate::core::{
    BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, RepoRef, TtlSeconds,
};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::nix_binary_cache::NixTrustedPublicKeys;
use crate::policy::PolicyConfig;
use crate::secret::{SecretError, SecretKey};
use crate::vm_git::VmGitPushBodyLimits;
use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};
use crate::vm_http::{VmHttpGitCloneConfig, VmHttpNixCacheConfig};

pub(super) const TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
pub(super) const SECOND_TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example-2:KinekIvGUnCJ2dP5u+7MmV9svoga1i9pbI98OXh+zZg=";

#[derive(Default)]
pub(super) struct InMemStore(StdMutex<std::collections::HashMap<String, String>>);

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

pub(super) fn make_state() -> Arc<BrokerState<InMemStore>> {
    make_state_with_audit(AuditLog::open_in_memory().unwrap())
}

pub(super) fn make_state_with_audit(audit: AuditLog) -> Arc<BrokerState<InMemStore>> {
    let key = SecretKey::new("gh-app-pk").unwrap();
    let mut apps = BTreeMap::new();
    apps.insert(
        AgentKind::Claude,
        GitHubAppConfig {
            app_id: 42,
            installation_id: 999,
            installation_owner: "o".into(),
            private_key_secret: key,
            api_base: "http://127.0.0.1".into(),
        },
    );
    Arc::new(BrokerState {
        audit: Arc::new(audit),
        minter: GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap()),
        secrets: InMemStore::default(),
        policy: PolicyConfig {
            writable_repos: Vec::<RepoRef>::new(),
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

pub(super) fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

pub(super) fn write_fake_tool(
    dir: &Path,
    args_log: &Path,
    env_path_log: &Path,
    env_log: &Path,
) -> PathBuf {
    let path = dir.join("fake-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"run\" ]; then\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--env-file\" ]; then\n\
             printf '%s\\n' \"$2\" > {env_path_log}\n\
             cat \"$2\" > {env_log}\n\
             fi\n\
             shift\n\
             done\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'ok' ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
        env_path_log = shell_quote(env_path_log),
        env_log = shell_quote(env_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Like [`write_fake_tool`] but never signals a bootstrap outcome — the
/// inspect always reports "pending". Used to exercise the bootstrap wait's
/// timeout path (the default tool now reports `ok`, since every start waits).
pub(super) fn write_fake_pending_bootstrap_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-pending-bootstrap-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Like [`write_fake_pending_bootstrap_tool`] but the bootstrap *inspect* exec
/// hangs (via `exec sleep`) rather than returning. Exercises the wait's
/// per-exec deadline: without it, the elapsed check (which only runs *after* an
/// exec returns) never fires and the wait blocks forever on a wedged guest
/// exec. The release exec touches the broker-ready path (not the
/// bootstrap-failed path), so it still returns fast.
pub(super) fn write_fake_hung_inspect_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-hung-inspect-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) exec sleep 30 ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Like [`write_fake_pending_bootstrap_tool`] but the bootstrap *inspect* exec
/// floods stdout with ~2 MiB of output — a stand-in for a hostile guest whose
/// failure file `cat`s to an arbitrary size. Exercises the wait's byte cap:
/// without it, the whole payload would be buffered into host memory.
pub(super) fn write_fake_oversized_inspect_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-oversized-inspect-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*)\n\
             printf 'failed\\n'\n\
             dd if=/dev/zero bs=1048576 count=2 2>/dev/null | tr '\\000' a ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Emulates a guest holding a *large* `bootstrap-failed` file whose actionable
/// error is the final line. The fake honours whatever the inspect command asks
/// for: if the script cooperatively tails (`tail -c`), it returns a bounded
/// tail (ending in the sentinel, under the capture cap); otherwise it floods
/// the whole ~2 MiB file, so a host-side head-truncation drops the sentinel.
/// This lets a test assert the daemon preserves the diagnosis tail rather than
/// discarding it as oversized.
pub(super) fn write_fake_large_failure_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-large-failure-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*)\n\
             printf 'failed\\n'\n\
             case \"${{5:-}}\" in\n\
             *'tail -c'*) dd if=/dev/zero bs=1024 count=32 2>/dev/null | tr '\\000' a ;;\n\
             *) dd if=/dev/zero bs=1048576 count=2 2>/dev/null | tr '\\000' a ;;\n\
             esac\n\
             printf 'NIX_ERROR_SENTINEL\\n' ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

pub(super) fn write_fake_network_create_failure_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-failing-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"create\" ]; then\n\
             exit 42\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Fail only when invoked as the `pf-helper remove ...` step of a stop plan.
///
/// All non-pf-helper invocations (`container list/rm/stop/delete`,
/// `container network ...`) take `rm`/`stop`/`delete`/`list` as `$2`, so
/// matching on `$2 = "remove"` isolates the firewall-removal failure from
/// the VM and network teardown probes.
pub(super) fn write_fake_pf_remove_failure_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-pf-remove-failure-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$2\" = \"remove\" ]; then\n\
             exit 7\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// Like [`write_fake_tool`] (so a session starts cleanly), but the
/// `pf-helper remove` step of a stop plan exits non-zero. The agent VM and the
/// network both probe absent, so the stop reaches — and fails at — the firewall
/// removal, exercising the daemon's teardown-failure handling on a *genuine*
/// managed session (a `Stop` cleanup error, not a missing state record).
pub(super) fn write_fake_stop_firewall_remove_failure_tool(
    dir: &Path,
    args_log: &Path,
    env_path_log: &Path,
    env_log: &Path,
) -> PathBuf {
    let path = dir.join("fake-stop-firewall-remove-failure-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$2\" = \"remove\" ]; then\n\
             exit 7\n\
             fi\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"run\" ]; then\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--env-file\" ]; then\n\
             printf '%s\\n' \"$2\" > {env_path_log}\n\
             cat \"$2\" > {env_log}\n\
             fi\n\
             shift\n\
             done\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'ok' ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
        env_path_log = shell_quote(env_path_log),
        env_log = shell_quote(env_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// A stop/reconcile-only fake whose `container list --all` echoes whatever VM
/// names are listed (one per line) in `present_file`, while removal commands are
/// no-ops that never clear it. The agent VM therefore never probes absent and VM
/// cleanup fails after the bounded retries — the fixture for proving teardown of
/// a still-present VM preserves the PF anchor. `network list` reports nothing
/// (absent); the `pf-helper` steps are plain no-ops so their *presence* in the
/// args log is what a test checks.
pub(super) fn write_fake_vm_present_tool(
    dir: &Path,
    args_log: &Path,
    present_file: &Path,
) -> PathBuf {
    let path = dir.join("fake-vm-present-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"list\" ] && [ \"$2\" = \"--all\" ]; then\n\
             cat {present_file} 2>/dev/null || true\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
        present_file = shell_quote(present_file),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

pub(super) fn write_fake_workspace_failure_tool(
    dir: &Path,
    args_log: &Path,
    env_path_log: &Path,
    env_log: &Path,
) -> PathBuf {
    let path = dir.join("fake-workspace-failure-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"run\" ]; then\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--env-file\" ]; then\n\
             printf '%s\\n' \"$2\" > {env_path_log}\n\
             cat \"$2\" > {env_log}\n\
             fi\n\
             shift\n\
             done\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'failed\\nsimulated workspace failure\\n' ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
        env_path_log = shell_quote(env_path_log),
        env_log = shell_quote(env_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

pub(super) fn write_fake_workspace_success_tool(
    dir: &Path,
    args_log: &Path,
    env_path_log: &Path,
    env_log: &Path,
) -> PathBuf {
    let path = dir.join("fake-workspace-success-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"run\" ]; then\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--env-file\" ]; then\n\
             printf '%s\\n' \"$2\" > {env_path_log}\n\
             cat \"$2\" > {env_log}\n\
             fi\n\
             shift\n\
             done\n\
             fi\n\
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'ok' ;;\n\
             esac\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote(args_log),
        env_path_log = shell_quote(env_path_log),
        env_log = shell_quote(env_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

pub(super) fn agent_vm_pool() -> AgentNetworkPool {
    AgentNetworkPool::new(
        Ipv4Cidr::new("192.168.0.0".parse().unwrap(), 16).unwrap(),
        Ipv6Cidr::new("fd83:b6f2:e57::".parse().unwrap(), 48).unwrap(),
    )
    .unwrap()
}

pub(super) fn daemon_config(
    dir: &Path,
    fake_tool: &Path,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_with_subnet_range(dir, fake_tool, 252, 253)
}

/// A daemon config whose broker serves a configured pre-warm cache dir, so a
/// started session advertises the strict `/v1/nix/prewarm` substituter to the
/// guest warm.
pub(super) fn daemon_config_with_prewarm_dir(
    dir: &Path,
    fake_tool: &Path,
    prewarm_dir: &Path,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_with_prewarm_dir_and_placement(dir, fake_tool, prewarm_dir, BrokerPlacement::Host)
}

/// A daemon config with a configured pre-warm dir under a chosen broker
/// placement. Both placements serve the pre-warm cache (host directly, vm via the
/// re-pointed dir + read-only mount), so both advertise the strict substituter.
pub(super) fn daemon_config_with_prewarm_dir_and_placement(
    dir: &Path,
    fake_tool: &Path,
    prewarm_dir: &Path,
    broker_placement: BrokerPlacement,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner(
        dir,
        fake_tool,
        252,
        253,
        Some(prewarm_dir.to_path_buf()),
        broker_placement,
    )
}

pub(super) fn daemon_config_with_subnet_range(
    dir: &Path,
    fake_tool: &Path,
    subnet_index_min: u16,
    subnet_index_max: u16,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner(
        dir,
        fake_tool,
        subnet_index_min,
        subnet_index_max,
        None,
        BrokerPlacement::Host,
    )
}

pub(super) fn daemon_config_with_broker_placement(
    dir: &Path,
    fake_tool: &Path,
    broker_placement: BrokerPlacement,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner(dir, fake_tool, 252, 253, None, broker_placement)
}

fn daemon_config_inner(
    dir: &Path,
    fake_tool: &Path,
    subnet_index_min: u16,
    subnet_index_max: u16,
    nix_prewarm_cache_dir: Option<PathBuf>,
    broker_placement: BrokerPlacement,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    let state_store = AgentVmSessionStateStore::new(dir.join("state"));
    // The vm placement requires a broker image; supply one so vm-placement
    // configs construct (the start path then branches on placement).
    let broker_image = match broker_placement {
        BrokerPlacement::Host => None,
        BrokerPlacement::Vm => Some(ContainerImage::new("writ-broker-vm:latest").unwrap()),
    };
    let lifecycle = AgentVmLifecycleRuntimeConfig::new(
        agent_vm_pool(),
        subnet_index_min,
        subnet_index_max,
        state_store.clone(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        broker_placement,
        ContainerImage::new("alpine:latest").unwrap(),
        broker_image,
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(fake_tool, fake_tool, fake_tool),
    )
    .unwrap();
    let credential =
        GitCredentialBoundary::new(fake_tool, GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap())
            .unwrap();
    let git_clone = VmHttpGitCloneConfig::new(
        fake_tool,
        credential,
        dir.join("git-work"),
        std::time::Duration::from_secs(1),
        1024 * 1024,
    )
    .unwrap();
    let nix_cache = VmHttpNixCacheConfig::new_with_trusted_public_keys(
        "http://127.0.0.1:9",
        1024 * 1024,
        1024 * 1024,
        NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap(),
    )
    .unwrap()
    .with_local_cache_dirs(nix_prewarm_cache_dir.iter().cloned().collect());
    (
        AgentVmDaemonRuntimeConfig::new(
            lifecycle,
            VmHttpRuntimeConfig::new(
                "0.0.0.0".parse().unwrap(),
                BrokerPortRange::new(1024, 65535).unwrap(),
                git_clone,
                nix_cache,
                dir.join("agent-runs"),
                dir.join("git-push-staging"),
                VmGitPushBodyLimits::new(65 * 1024 * 1024, 16 * 1024, 64 * 1024 * 1024).unwrap(),
            )
            .with_nix_prewarm_cache_dir(nix_prewarm_cache_dir),
        )
        .unwrap(),
        state_store,
    )
}

pub(super) fn occupy_subnet(store: &AgentVmSessionStateStore, index: u16) {
    let plan = AgentVmSessionPlan::new(
        SessionId::from_uuid(uuid::Uuid::from_u128(0x1000 + u128::from(index))),
        agent_vm_pool(),
        index,
        BrokerPorts::new([BrokerPort::new(51375).unwrap()]).unwrap(),
        BrokerPortRange::new(1024, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
    )
    .unwrap();
    store.create_starting(&plan).unwrap();
}
