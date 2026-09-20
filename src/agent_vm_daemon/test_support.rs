//! Shared fixtures for the `agent_vm_daemon` test modules: the in-memory
//! secret store and broker state, the fake `container`/`pf-helper` tools
//! the lifecycle drives, and the daemon-config constructors.
//!
//! Hoisted here so the per-concern `*_tests` modules and the inline `spec`
//! reuse one set of constructors. `super::*` re-exports the production
//! items and the parent's private `crate::*` imports; the explicit `use`s
//! below cover the test-only constructors these helpers call.
use super::*;
use crate::test_support::claude_broker_state;
pub(super) use crate::test_support::{InMemorySecretStore, shell_quote_path};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use writ_core::byte_size::ByteSize;

use crate::agent_vm_locked_admission::{
    AdmittedProfile, LockedV1Admission, LockedV1Fact, ProvenPlatform,
};
use crate::audit::AuditLog;
use crate::core::{BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr};
use crate::nix_binary_cache::NixTrustedPublicKeys;
use crate::vm_git::VmGitPushBodyLimits;
use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};
use crate::vm_http::{VmHttpGitCloneConfig, VmHttpNixCacheConfig};

pub(super) const TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
pub(super) const SECOND_TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example-2:KinekIvGUnCJ2dP5u+7MmV9svoga1i9pbI98OXh+zZg=";

pub(super) fn make_state() -> Arc<BrokerState<InMemorySecretStore>> {
    make_state_with_audit(AuditLog::open_in_memory().unwrap())
}

/// A broker state whose agent-run bounds are as small as they go: one
/// running, one waiting.
///
/// For the tests about what happens to a request the bound refuses.
pub(super) fn make_state_with_one_run_admitted() -> Arc<BrokerState<InMemorySecretStore>> {
    let one = std::num::NonZeroUsize::new(1).unwrap();
    let mut state = claude_broker_state("http://127.0.0.1", "o");
    state.audit = Arc::new(AuditLog::open_in_memory().unwrap());
    state.agent_run_slots = crate::server::AgentRunSlots::new(one, one).unwrap();
    Arc::new(state)
}

pub(super) fn make_state_with_audit(audit: AuditLog) -> Arc<BrokerState<InMemorySecretStore>> {
    let mut state = claude_broker_state("http://127.0.0.1", "o");
    state.audit = Arc::new(audit);
    Arc::new(state)
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
        args_log = shell_quote_path(args_log),
        env_path_log = shell_quote_path(env_path_log),
        env_log = shell_quote_path(env_log),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// What every lifecycle test starts from: a tempdir, the three logs the
/// default fake `container` tool writes, and the daemon plus state store that
/// [`daemon_config`] builds around that tool. Destructure the names a test
/// uses; the tempdir, and the fixture with it, goes when the value does.
pub(super) struct Harness {
    pub(super) dir: tempfile::TempDir,
    /// Every argv the fake tool was invoked with, one line each.
    pub(super) args_log: PathBuf,
    /// The `--env-file` path the fake `run` was handed.
    pub(super) env_path_log: PathBuf,
    /// That env file's contents.
    pub(super) env_log: PathBuf,
    pub(super) state_store: AgentVmSessionStateStore,
    pub(super) daemon: AgentVmDaemon,
}

impl Harness {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        Self {
            dir,
            args_log,
            env_path_log,
            env_log,
            state_store,
            daemon: AgentVmDaemon::new(config),
        }
    }
}

/// Like [`write_fake_tool`] but never signals a bootstrap outcome — the
/// inspect always reports "pending". Exercises the bootstrap wait's timeout
/// path; the default tool reports `ok`, since every start waits.
pub(super) fn write_fake_pending_bootstrap_tool(dir: &Path, args_log: &Path) -> PathBuf {
    let path = dir.join("fake-pending-bootstrap-tool");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             exit 0\n",
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
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
        args_log = shell_quote_path(args_log),
        env_path_log = shell_quote_path(env_path_log),
        env_log = shell_quote_path(env_log),
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
        args_log = shell_quote_path(args_log),
        present_file = shell_quote_path(present_file),
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
        args_log = shell_quote_path(args_log),
        env_path_log = shell_quote_path(env_path_log),
        env_log = shell_quote_path(env_log),
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
        args_log = shell_quote_path(args_log),
        env_path_log = shell_quote_path(env_path_log),
        env_log = shell_quote_path(env_log),
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

/// A config under a chosen placement *and* profile, for the tests about which
/// refusal an operator gets when both would refuse.
pub(super) fn daemon_config_with_placement_and_profile(
    dir: &Path,
    fake_tool: &Path,
    broker_placement: BrokerPlacement,
    ipv6_profile: ConfiguredIpv6Profile,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner_with_profile(
        dir,
        fake_tool,
        252,
        253,
        None,
        broker_placement,
        ipv6_profile,
    )
}

/// A host-placement config under a chosen IPv6 profile, for the tests about
/// which profiles admit a session.
pub(super) fn daemon_config_with_ipv6_profile(
    dir: &Path,
    fake_tool: &Path,
    ipv6_profile: ConfiguredIpv6Profile,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner_with_profile(
        dir,
        fake_tool,
        252,
        253,
        None,
        BrokerPlacement::Host,
        ipv6_profile,
    )
}

fn daemon_config_inner(
    dir: &Path,
    fake_tool: &Path,
    subnet_index_min: u16,
    subnet_index_max: u16,
    nix_prewarm_cache_dir: Option<PathBuf>,
    broker_placement: BrokerPlacement,
) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
    daemon_config_inner_with_profile(
        dir,
        fake_tool,
        subnet_index_min,
        subnet_index_max,
        nix_prewarm_cache_dir,
        broker_placement,
        // The profile that actually starts a session on current Apple
        // `container`, and so the one these fixtures should exercise.
        ConfiguredIpv6Profile::Ipv4OnlyNoGuestIpv6,
    )
}

#[allow(clippy::too_many_arguments)]
fn daemon_config_inner_with_profile(
    dir: &Path,
    fake_tool: &Path,
    subnet_index_min: u16,
    subnet_index_max: u16,
    nix_prewarm_cache_dir: Option<PathBuf>,
    broker_placement: BrokerPlacement,
    ipv6_profile: ConfiguredIpv6Profile,
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
        ipv6_profile,
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
        ByteSize::mib(1),
    )
    .unwrap();
    let nix_cache = VmHttpNixCacheConfig::new_with_trusted_public_keys(
        "http://127.0.0.1:9",
        ByteSize::mib(1),
        ByteSize::mib(1),
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
                dir.join("git-push-staging"),
                VmGitPushBodyLimits::new(
                    ByteSize::from_bytes(65 * 1024 * 1024),
                    ByteSize::kib(16),
                    ByteSize::mib(64),
                )
                .unwrap(),
            )
            .with_nix_prewarm_cache_dir(nix_prewarm_cache_dir),
            crate::config::AgentRunLogRoot::check(dir.join("agent-runs")).unwrap(),
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

// --- the locked profile -----------------------------------------------------

/// The digest the locked fixture's `container inspect` reports, and the one
/// [`locked_admission`] admits. Any other and the readback refuses the start.
pub(super) const LOCKED_IMAGE_DIGEST: &str =
    "sha256:226205c93c1bc4148f691c0162118b39d8fca907691e9fc620bddce2dec6567e";

/// An admission for the image the locked fixture serves.
///
/// Built through [`ProvenPlatform::parse`], so the three facts are the ones
/// the real probes would have produced; what it skips is the gathering, which
/// Stage E2c-3c wires up and Stage D already tests over the whole grid.
pub(super) fn locked_admission(image_digest: &str) -> AdmittedProfile {
    AdmittedProfile::Ipv4OnlyLockedV1(LockedV1Admission::claimed_for_test(
        ProvenPlatform::parse(
            "container CLI version 0.0.0 (build: synthetic, commit: 0000000)",
            "0Z0",
            image_digest,
        )
        .unwrap(),
    ))
}

/// What the locked readback sees: a container matching the locked launch.
fn locked_inspect_doc(digest: &str) -> String {
    serde_json::json!([{
        "configuration": {
            "image": {"descriptor": {"digest": digest}, "reference": "alpine:latest"},
            "capAdd": ["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_ADMIN"],
            "capDrop": ["ALL"],
            "readonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq"],
            "useInit": false,
            "initProcess": {
                "executable": "/sbin/writ-agent-vm-guest-init",
                "user": {"id": {"uid": 0, "gid": 0}}
            }
        }
    }])
    .to_string()
}

/// A `pf-helper install` report that completed every phase, for the session
/// the locked start installs its attached anchor for.
fn locked_install_report(session_id: SessionId) -> String {
    format!(
        r#"{{"protocol":"{name}","version":{version},"anchor":"writ/session/{session_id}","interfaces":["bridge100","vmenet0"],"phase":"reresolve"}}"#,
        name = crate::agent_vm_pf_helper_protocol::PF_HELPER_PROTOCOL_NAME,
        version = crate::agent_vm_pf_helper_protocol::PF_HELPER_PROTOCOL_VERSION,
    )
}

/// How the locked fixture's guest behaves once it is released.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum LockedGuest {
    /// Reports a successful bootstrap.
    BootstrapsCleanly,
    /// Reports a bounded failure reason, the way the locked scripts' failure
    /// emitter does.
    ReportsBootstrapFailure,
}

/// A fake `container` + `pf-helper` + `sudo` for a whole locked session.
///
/// One script in all three roles, because [`daemon_config`] gives the daemon
/// one tool path for all three. It is stateful in one respect that matters:
/// the guest's log gains its bootstrap record only after the release, so a
/// host that read the post-release channel early would find nothing, and one
/// that released before installing the anchor would be visible in the order
/// of the argv log.
///
/// It answers no `exec`, deliberately. A locked session must never run one,
/// and a fixture that quietly served them would let that regress unseen.
pub(super) fn write_fake_locked_tool(
    dir: &Path,
    args_log: &Path,
    env_log: &Path,
    session_id: SessionId,
    guest: LockedGuest,
) -> PathBuf {
    let path = dir.join("fake-locked-tool");
    fs::write(
        dir.join("locked-inspect.json"),
        locked_inspect_doc(LOCKED_IMAGE_DIGEST),
    )
    .unwrap();
    fs::write(
        dir.join("locked-report.json"),
        locked_install_report(session_id),
    )
    .unwrap();
    fs::write(
        dir.join("locked-ready.txt"),
        format!("{}\n", writ_guest_init::record::SECURITY_READY_LINE),
    )
    .unwrap();
    let bootstrap = match guest {
        LockedGuest::BootstrapsCleanly => "writ-agent-vm-bootstrap ok".to_string(),
        LockedGuest::ReportsBootstrapFailure => {
            "writ-agent-vm-bootstrap failed writ-vm workspace init failed with exit 1".to_string()
        }
    };
    fs::write(dir.join("locked-bootstrap.txt"), format!("{bootstrap}\n")).unwrap();
    let script = format!(
        r#"#!/bin/sh
# `sudo` is this same script here, so an invocation whose first argument is
# this script's own path is one: drop it and read the real command.
[ "$1" = "$0" ] && shift
# One line per invocation, whatever the arguments contain: the create is
# handed a whole shell script, and a log that let its lines through would put
# words from the guest's own script where a test looks for subcommands.
printf '%s' "$*" | tr '\n' ' ' >> {args_log}
printf '\n' >> {args_log}
case "$1" in
  network)
    if [ "$2" = "inspect" ]; then
      printf '%s\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'
    fi ;;
  install) cat {root}/locked-report.json ;;
  create)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--env-file" ]; then cat "$2" > {env_log}; fi
      shift
    done ;;
  inspect) cat {root}/locked-inspect.json ;;
  logs)
    cat {root}/locked-ready.txt
    if [ -f {root}/released ]; then cat {root}/locked-bootstrap.txt; fi ;;
  kill) : > {root}/released ;;
esac
exit 0
"#,
        args_log = shell_quote_path(args_log),
        env_log = shell_quote_path(env_log),
        root = shell_quote_path(dir),
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

/// A host the locked profile's admission probes read differently.
///
/// Every one of them refuses, because the shipped allowlist is empty — but
/// they refuse over different facts, and the point of sweeping them is that
/// what a refusal *costs* must not depend on which fact refused it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum LockedProbeHost {
    /// Every probe answers, and the platform is simply not in the record.
    Unrecorded,
    /// The PF helper is too old to bound this daemon.
    OldHelper,
    /// The guest image declares no isolation ABI.
    ImageWithoutAbiLabel,
    /// Nothing answers at all.
    Silent,
    /// Every probe answers, but slowly, and each one refuses to overlap with
    /// another: if a second probe starts while one is in flight it records
    /// the fact. For the test that writd gathers admission one at a time.
    RefusesToOverlap,
}

impl LockedProbeHost {
    /// The hosts the refusal sweep runs over. `RefusesToOverlap` is left out:
    /// it is about concurrency, not about which fact refuses, and it sleeps.
    pub(super) const ALL: [Self; 4] = [
        Self::Unrecorded,
        Self::OldHelper,
        Self::ImageWithoutAbiLabel,
        Self::Silent,
    ];

    /// Which fact this host's refusal is about.
    ///
    /// Asserted by the sweep, so a fixture that stopped producing the host it
    /// names fails rather than quietly making two cases the same one.
    pub(super) fn refused_over(self) -> LockedV1Fact {
        match self {
            // Every fact reads; the platform is simply not in the record, and
            // the first level of the allowlist it leaves is the CLI.
            Self::Unrecorded => LockedV1Fact::ContainerCli,
            Self::OldHelper => LockedV1Fact::HelperProtocol,
            Self::ImageWithoutAbiLabel => LockedV1Fact::ImageIsolationAbi,
            // Nothing answers, so the first fact checked is the first that
            // cannot be read.
            Self::Silent => LockedV1Fact::HelperProtocol,
            Self::RefusesToOverlap => LockedV1Fact::ContainerCli,
        }
    }
}

/// A fake `container` + `pf-helper` + `sudo` that answers the five admission
/// probes as `host` would, and logs every argv it was given.
///
/// The log is what the "a refusal creates nothing" test reads: it has to
/// contain the probes and nothing else.
pub(super) fn write_fake_locked_probe_tool(
    dir: &Path,
    args_log: &Path,
    host: LockedProbeHost,
) -> PathBuf {
    let path = dir.join("fake-locked-probe-tool");
    let helper_version = match host {
        LockedProbeHost::OldHelper => 1,
        _ => crate::agent_vm_pf_helper_protocol::PF_HELPER_PROTOCOL_VERSION,
    };
    let labels = match host {
        LockedProbeHost::ImageWithoutAbiLabel => String::new(),
        _ => format!(
            r#""{label}":"{version}""#,
            label = writ_guest_init::record::ISOLATION_ABI_LABEL,
            version = writ_guest_init::record::ISOLATION_ABI_VERSION,
        ),
    };
    fs::write(
        dir.join("probe-helper-protocol.out"),
        format!(
            "{}\n",
            crate::agent_vm_pf_helper_protocol::PfHelperProtocolDoc::with_version(helper_version)
                .render()
        ),
    )
    .unwrap();
    fs::write(
        dir.join("probe-preflight.out"),
        format!(
            "{}\n",
            crate::agent_vm_pf_helper_protocol::PfHelperPreflightDoc::new(
                crate::agent_vm_firewall::PfPreflightReport {
                    pf_enabled: true,
                    session_anchor: crate::agent_vm_firewall::SessionAnchorPlacement::First,
                    pass_translation_rules: Vec::new(),
                },
                crate::agent_vm_pf_helper_policy::PfHelperPolicy::new(
                    agent_vm_pool(),
                    BrokerPortRange::new(49152, 65535).unwrap(),
                ),
            )
            .render()
        ),
    )
    .unwrap();
    // The shape `container image inspect` really prints, which is what
    // `ImageInspection::parse` really requires: the digest under
    // `configuration.descriptor`, and the labels three levels into the
    // variant's config. A fixture that only *looked* plausible made two of
    // these hosts refuse over the same fact, which is how a sweep over four
    // hosts became a sweep over three.
    fs::write(
        dir.join("probe-image-inspect.out"),
        format!(
            r#"[{{"configuration":{{"descriptor":{{"digest":"{digest}"}},"name":"alpine:latest"}},
                 "variants":[{{"config":{{"config":{{"Labels":{{{labels}}}}}}}}}]}}]"#,
            digest = LOCKED_IMAGE_DIGEST,
        ),
    )
    .unwrap();
    let script = format!(
        r#"#!/bin/sh
# Logged *before* the sudo shift, so a line is the argv as invoked — which is
# what the caller's own probe plan says it should be.
printf '%s' "$*" | tr '\n' ' ' >> {args_log}
printf '\n' >> {args_log}
# `sudo` is this same script here, so an invocation whose first argument is
# this script's own path is one: drop it and read the real command.
[ "$1" = "$0" ] && shift
# Only the admission probes behave as `host` says. Everything else — the
# teardown commands a reconcile runs — succeeds quietly, so a test can tell a
# host that refuses admission from one that cannot be cleaned up.
case "$1" in
  protocol-version|preflight|image|--version|-buildVersion) ;;
  *) exit 0 ;;
esac
if [ "{host:?}" = Silent ]; then exit 3; fi
if [ "{host:?}" = RefusesToOverlap ]; then
  # Detected by the probe itself rather than timed by the test: if a second
  # gathering is in flight, this file exists, and that is a fact about writd
  # rather than about how fast this machine is. The sleep only makes the
  # overlap likely when there is nothing stopping it.
  if [ -e {root}/probing ]; then printf '%s\n' "$*" >> {root}/overlap.log; fi
  : > {root}/probing
  sleep 0.2
  rm -f {root}/probing
fi
case "$1" in
  protocol-version) exec cat {root}/probe-helper-protocol.out ;;
  preflight) exec cat {root}/probe-preflight.out ;;
  image) exec cat {root}/probe-image-inspect.out ;;
  --version) printf 'container CLI version 0.0.0 (build: synthetic, commit: 0000000)\n' ;;
esac
exit 0
"#,
        args_log = shell_quote_path(args_log),
        root = shell_quote_path(dir),
        host = host,
    );
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}
