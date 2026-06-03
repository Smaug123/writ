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

// The two guest setup scripts share a nix.conf / netrc prologue that is
// byte-identical save for three points: the workspace script parses
// positional repo/destination/warm arguments up front, creates the
// `/run/writ-agent-vm` runtime dir, and enables `flakes`. The prologue is
// held once as the fragments below and assembled per script, so the
// security-critical netrc write and substituter/trusted-keys block live
// in a single place.

/// Env-var guards plus the trailing blank line, shared by both scripts.
const GUEST_NIX_PROLOGUE_HEAD: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${WRIT_NIX_TRUSTED_PUBLIC_KEYS:=}"
: "${NIX_CONF_DIR:?}"

"#;

/// Cache-URL validation, host derivation, and netrc-dir resolution, up to
/// (but not including) the `mkdir -p` line.
const GUEST_NIX_PROLOGUE_MIDDLE: &str = r#"case "$WRIT_NIX_CACHE_URL" in
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
"#;

/// `umask`, the netrc write, and the opening brace of the nix.conf block,
/// up to (but not including) the `experimental-features` line.
const GUEST_NIX_PROLOGUE_NETRC: &str = r#"umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
"#;

/// The remainder of the nix.conf block, after the `experimental-features`
/// line through the closing redirect.
const GUEST_NIX_PROLOGUE_NIXCONF_REST: &str = r#"  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"
"#;

/// Positional-argument parse the workspace script runs between the guards
/// and the cache validation; the plain nix-setup script has none.
const GUEST_WORKSPACE_POSITIONAL: &str = r#"repo="$1"
destination="$2"
warm="$3"
shift 3

"#;

/// Tail of the plain nix-setup script: exec the wrapped guest command.
const GUEST_NIX_SETUP_TAIL: &str = r#"
exec "$@"
"#;

/// Tail of the workspace script: wait for the broker, run the workspace
/// init, then run the agent as a child so the container outlives it.
const GUEST_WORKSPACE_BOOTSTRAP_TAIL: &str = r#"
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

/// Assemble a guest setup script from the shared nix prologue plus the
/// per-script `positional` parse, `mkdir_line`, `features_line`, and
/// `tail`. See [`nix_setup_script`] and [`workspace_bootstrap_script`].
fn build_guest_nix_setup_script(
    positional: &str,
    mkdir_line: &str,
    features_line: &str,
    tail: &str,
) -> String {
    let mut script = String::with_capacity(2048);
    script.push_str(GUEST_NIX_PROLOGUE_HEAD);
    script.push_str(positional);
    script.push_str(GUEST_NIX_PROLOGUE_MIDDLE);
    script.push_str(mkdir_line);
    script.push('\n');
    script.push_str(GUEST_NIX_PROLOGUE_NETRC);
    script.push_str(features_line);
    script.push('\n');
    script.push_str(GUEST_NIX_PROLOGUE_NIXCONF_REST);
    script.push_str(tail);
    script
}

/// The non-workspace guest setup script: configure the nix cache, then
/// `exec` the wrapped guest command. Does not enable flakes.
pub(super) fn nix_setup_script() -> String {
    build_guest_nix_setup_script(
        "",
        r#"mkdir -p "$netrc_dir" "$NIX_CONF_DIR""#,
        r#"  printf 'experimental-features = nix-command\n'"#,
        GUEST_NIX_SETUP_TAIL,
    )
}

/// The workspace guest setup script: the shared nix prologue (with flakes
/// and the `/run/writ-agent-vm` runtime dir), the workspace init, then the
/// agent run.
pub(super) fn workspace_bootstrap_script() -> String {
    build_guest_nix_setup_script(
        GUEST_WORKSPACE_POSITIONAL,
        r#"mkdir -p "$netrc_dir" "$NIX_CONF_DIR" /run/writ-agent-vm"#,
        r#"  printf 'experimental-features = nix-command flakes\n'"#,
        GUEST_WORKSPACE_BOOTSTRAP_TAIL,
    )
}

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
        &nix_setup_script(),
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
        &workspace_bootstrap_script(),
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
                nix_setup_script(),
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
                workspace_bootstrap_script(),
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
