//! What the authority-bearing guest executes, and the `sh -c` wrappers
//! that prepend the nix-cache/netrc setup (and, for workspace runs, the
//! `writ-vm workspace init` bootstrap) around the caller's command.
//!
//! These are pure functions over the request facts plus the two embedded
//! guest shell scripts; the parent daemon calls them while assembling a
//! session plan.

use std::path::PathBuf;

use crate::agent_run::AgentRunId;
use crate::audit::AgentVmWorkspaceBootstrapAuditRecord;
use crate::core::{AgentKind, SessionId, UnixMillis};
use crate::vm_git::{
    AgentVmWorkspaceBootstrap, DEFAULT_DEVSHELL_ATTR, DEFAULT_WORKSPACE_BRANCH, WorkspaceWarmMode,
    default_workspace_destination, nix_develop_command_args,
};

use super::AgentVmDaemonError;

pub(super) const AGENT_VM_GUEST_NIX_SETUP_SCRIPT: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${WRIT_NIX_TRUSTED_PUBLIC_KEYS:=}"
: "${NIX_CONF_DIR:?}"

case "$WRIT_NIX_CACHE_URL" in
  http://*|https://*) ;;
  *) echo "WRIT_NIX_CACHE_URL must be http or https" >&2; exit 64 ;;
esac

cache_authority="${WRIT_NIX_CACHE_URL#http://}"
if [ "$cache_authority" = "$WRIT_NIX_CACHE_URL" ]; then
  cache_authority="${WRIT_NIX_CACHE_URL#https://}"
fi
cache_host="${cache_authority%%/*}"
cache_host="${cache_host%%:*}"
if [ -z "$cache_host" ]; then
  echo "WRIT_NIX_CACHE_URL has no host" >&2
  exit 64
fi

netrc_dir="${WRIT_NIX_NETRC%/*}"
if [ "$netrc_dir" = "$WRIT_NIX_NETRC" ]; then
  netrc_dir=.
fi
mkdir -p "$netrc_dir" "$NIX_CONF_DIR"
umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
  printf 'experimental-features = nix-command\n'
  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"

exec "$@"
"#;

pub(super) const AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${WRIT_NIX_TRUSTED_PUBLIC_KEYS:=}"
: "${NIX_CONF_DIR:?}"

repo="$1"
destination="$2"
warm="$3"
shift 3

case "$WRIT_NIX_CACHE_URL" in
  http://*|https://*) ;;
  *) echo "WRIT_NIX_CACHE_URL must be http or https" >&2; exit 64 ;;
esac

cache_authority="${WRIT_NIX_CACHE_URL#http://}"
if [ "$cache_authority" = "$WRIT_NIX_CACHE_URL" ]; then
  cache_authority="${WRIT_NIX_CACHE_URL#https://}"
fi
cache_host="${cache_authority%%/*}"
cache_host="${cache_host%%:*}"
if [ -z "$cache_host" ]; then
  echo "WRIT_NIX_CACHE_URL has no host" >&2
  exit 64
fi

netrc_dir="${WRIT_NIX_NETRC%/*}"
if [ "$netrc_dir" = "$WRIT_NIX_NETRC" ]; then
  netrc_dir=.
fi
mkdir -p "$netrc_dir" "$NIX_CONF_DIR" /run/writ-agent-vm
umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
  printf 'experimental-features = nix-command flakes\n'
  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"

while [ ! -f /run/writ-agent-vm/broker-ready ]; do
  sleep 0.2
done

set +e
writ-vm workspace init "$repo" "$destination" --warm "$warm" \
  > /run/writ-agent-vm/bootstrap.stdout \
  2> /run/writ-agent-vm/bootstrap.stderr
code=$?
set -e
if [ "$code" -ne 0 ]; then
  set +e
  {
    printf 'writ-vm workspace init failed with exit %s\n' "$code"
    if [ -s /run/writ-agent-vm/bootstrap.stderr ]; then
      printf '%s\n' 'stderr:'
      cat /run/writ-agent-vm/bootstrap.stderr
    fi
  } > /run/writ-agent-vm/bootstrap-failed
  set -e
  # Stay alive so the daemon can inspect bootstrap-failed before the lifecycle
  # cleanup path tears the VM down. Exiting here races the daemon's poller.
  while :; do sleep 3600; done
fi

rm -f /run/writ-agent-vm/bootstrap.stdout /run/writ-agent-vm/bootstrap.stderr
if ! cd "$destination"; then
  set +e
  printf 'workspace destination disappeared before agent exec: %s\n' "$destination" \
    > /run/writ-agent-vm/bootstrap-failed
  set -e
  while :; do sleep 3600; done
fi
touch /run/writ-agent-vm/bootstrap-ok
# Run the agent as a child rather than exec-ing it, so the container outlives
# the agent. Otherwise an agent that finishes (or crashes) within the
# daemon's poll interval can race the bootstrap-ok signal: the next poll
# would see a dying container instead of the ok file. The daemon owns
# teardown via the stop API.
set +e
"$@" > /run/writ-agent-vm/agent.stdout 2> /run/writ-agent-vm/agent.stderr
agent_code=$?
set -e
printf '%s\n' "$agent_code" > /run/writ-agent-vm/agent.exit
while :; do sleep 3600; done
"#;

pub(super) fn wrap_guest_command(
    workspace: Option<&AgentVmWorkspaceBootstrap>,
    guest_command: Vec<String>,
) -> Result<Vec<String>, AgentVmDaemonError> {
    match workspace {
        Some(workspace) => wrap_guest_command_with_workspace_bootstrap(workspace, guest_command),
        None => Ok(wrap_guest_command_with_nix_setup(guest_command)),
    }
}

fn wrap_guest_command_with_nix_setup(guest_command: Vec<String>) -> Vec<String> {
    shell_wrapped_command(
        AGENT_VM_GUEST_NIX_SETUP_SCRIPT,
        "writ-agent-vm-nix-setup",
        std::iter::empty::<String>(),
        guest_command,
    )
}

pub(super) fn wrap_guest_command_with_workspace_bootstrap(
    workspace: &AgentVmWorkspaceBootstrap,
    guest_command: Vec<String>,
) -> Result<Vec<String>, AgentVmDaemonError> {
    let destination = workspace_destination(workspace)?;
    let destination_arg = destination
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| AgentVmDaemonError::NonUtf8WorkspaceDestination(destination.clone()))?;
    Ok(shell_wrapped_command(
        AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT,
        "writ-agent-vm-workspace-bootstrap",
        [
            workspace.repo.to_string(),
            destination_arg,
            workspace_warm_arg(workspace.warm).to_string(),
        ],
        guest_command,
    ))
}

fn shell_wrapped_command(
    script: &str,
    argv0: &str,
    prefix_args: impl IntoIterator<Item = String>,
    guest_command: Vec<String>,
) -> Vec<String> {
    let mut wrapped = vec![
        "sh".to_string(),
        "-c".to_string(),
        script.to_string(),
        argv0.into(),
    ];
    wrapped.extend(prefix_args);
    wrapped.extend(guest_command);
    wrapped
}

pub(super) fn build_agent_run_guest_command(
    agent_kind: AgentKind,
    run_id: AgentRunId,
    warm: WorkspaceWarmMode,
) -> Vec<String> {
    let mut command = vec![
        "writ-vm".to_string(),
        "agent".to_string(),
        "run".to_string(),
        "--run-id".to_string(),
        run_id.to_string(),
        "--agent".to_string(),
        agent_kind.as_str().to_string(),
    ];
    if warm != WorkspaceWarmMode::DevShell {
        return command;
    }

    let mut wrapped = vec!["nix".to_string()];
    wrapped.extend(nix_develop_command_args(DEFAULT_DEVSHELL_ATTR));
    wrapped.append(&mut command);
    wrapped
}

fn workspace_destination(
    workspace: &AgentVmWorkspaceBootstrap,
) -> Result<PathBuf, AgentVmDaemonError> {
    let destination = workspace
        .destination
        .clone()
        .unwrap_or_else(|| default_workspace_destination(&workspace.repo));
    if !destination.is_absolute() {
        return Err(AgentVmDaemonError::RelativeWorkspaceDestination(
            destination,
        ));
    }
    Ok(destination)
}

pub(super) fn workspace_bootstrap_audit_record(
    session_id: SessionId,
    workspace: &AgentVmWorkspaceBootstrap,
) -> Result<AgentVmWorkspaceBootstrapAuditRecord, AgentVmDaemonError> {
    let destination = workspace_destination(workspace)?;
    let destination = destination
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| AgentVmDaemonError::NonUtf8WorkspaceDestination(destination.clone()))?;
    Ok(AgentVmWorkspaceBootstrapAuditRecord {
        session_id,
        requested_at: UnixMillis::now(),
        repo: workspace.repo.to_string(),
        destination,
        branch: DEFAULT_WORKSPACE_BRANCH.to_string(),
        warm: workspace_warm_arg(workspace.warm).to_string(),
    })
}

fn workspace_warm_arg(mode: WorkspaceWarmMode) -> &'static str {
    match mode {
        WorkspaceWarmMode::None => "none",
        WorkspaceWarmMode::Sources => "sources",
        WorkspaceWarmMode::DevShell => "devshell",
    }
}

/// Property-based specification for the guest-command wrappers.
///
/// The example tests in the sibling `guest_command_tests` module pin
/// specific scripts and argv shapes; this module asserts the framing
/// contract holds for *arbitrary* guest commands: the `sh -c <script>
/// <argv0>` prefix is exact, the caller's command is preserved verbatim
/// as the trailing argv, and no internal `writ-vm-*` sentinel path leaks
/// into the wrapped command.
#[cfg(test)]
mod spec {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn nix_setup_wrapper_preserves_guest_command_argv(
            guest_command in prop::collection::vec(any::<String>(), 1..16),
        ) {
            let wrapped = wrap_guest_command_with_nix_setup(guest_command.clone());
            prop_assert_eq!(&wrapped[..4], &[
                "sh".to_string(),
                "-c".to_string(),
                AGENT_VM_GUEST_NIX_SETUP_SCRIPT.to_string(),
                "writ-agent-vm-nix-setup".to_string(),
            ]);
            prop_assert_eq!(&wrapped[4..], guest_command.as_slice());
            // The wrapper-owned framing must not carry a broker-token
            // sentinel; the caller's command is arbitrary and preserved
            // verbatim above, so it is excluded from this check.
            prop_assert!(!wrapped[..4].join("\n").contains("writ-vm-"));
        }

        #[test]
        fn workspace_bootstrap_wrapper_preserves_guest_command_argv(
            guest_command in prop::collection::vec(any::<String>(), 1..16),
            warm in prop_oneof![
                Just(WorkspaceWarmMode::None),
                Just(WorkspaceWarmMode::Sources),
                Just(WorkspaceWarmMode::DevShell),
            ],
        ) {
            let workspace = AgentVmWorkspaceBootstrap {
                repo: "owner/repo".parse().unwrap(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm,
            };
            let wrapped = wrap_guest_command_with_workspace_bootstrap(&workspace, guest_command.clone()).unwrap();
            prop_assert_eq!(&wrapped[..4], &[
                "sh".to_string(),
                "-c".to_string(),
                AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.to_string(),
                "writ-agent-vm-workspace-bootstrap".to_string(),
            ]);
            prop_assert_eq!(&wrapped[4..7], &[
                "owner/repo".to_string(),
                "/workspace/repo".to_string(),
                workspace_warm_arg(warm).to_string(),
            ]);
            prop_assert_eq!(&wrapped[7..], guest_command.as_slice());
            // See the nix-setup property: the sentinel check covers only
            // the wrapper-owned framing (script, argv0, and the repo /
            // destination / warm arguments), not the arbitrary caller
            // command preserved verbatim above.
            prop_assert!(!wrapped[..7].join("\n").contains("writ-vm-"));
        }
    }
}
