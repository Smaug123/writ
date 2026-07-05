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
///
/// `build-users-group =` is pinned empty deliberately. The guest runs Nix as
/// root in a single-user, root-owned store with no `nixbld` build-users group,
/// but Nix defaults `build-users-group` to `nixbld` whenever euid is 0. Any
/// *local* build (which the `nix develop` warm now permits under
/// `max-jobs = 1`, and which the agent's own later Nix commands run at the
/// default non-zero `max-jobs`) would otherwise fail with "the group 'nixbld'
/// ... does not exist". Empty means "build as the calling user", i.e. root.
///
/// Running those builds as root — with no Nix build sandbox and the broker
/// token sitting in the netrc this same prologue just wrote — is acceptable
/// under writ's trust model: the broker, not anything inside the guest, is the
/// trust boundary (the guest VM is untrusted-by-design). The same untrusted,
/// repo-controlled code reaches that token by other means in the same VM
/// regardless of this setting, so it grants no escalation:
///   * the warm's own `nix develop --command true` sources the devShell
///     `shellHook` (arbitrary repo code) as root even at `max-jobs = 0`, with
///     this netrc already present (a strict pre-warm warm realises via
///     `print-dev-env` and runs no hook, but the agent's `nix develop`
///     wrapper sources it moments later regardless);
///   * the agent runs inside the same `nix develop` wrapper as root, holds the
///     broker token in its environment, and can trigger its own builds at the
///     default non-zero `max-jobs`, all reading the same persistent netrc.
///
/// `max-jobs = 1` only moves a malicious devShell build slightly earlier (warm
/// vs. the agent's own devShell entry); the root/token/netrc access is
/// identical either way. Sandboxing only the warm build would close no door the
/// agent leaves wide open. Genuinely keeping the token away from root would
/// need a different credential design (scoped, short-lived, never materialised
/// in a root-readable file) — a separate, larger change.
const GUEST_NIX_PROLOGUE_NIXCONF_REST: &str = r#"  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'build-users-group =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"
"#;

/// Claude Code defaults for both hand-run `claude` in a debug shell and the
/// managed adapter. `/root` is the intended root home in the guest passwd file;
/// older loaded images had `HOME=/`, so normalise that here before any workload
/// starts.
const GUEST_CLAUDE_SETTINGS: &str = r#"claude_home="${HOME:-/root}"
if [ "$claude_home" = / ]; then
  claude_home=/root
fi
HOME="$claude_home"
export HOME

claude_config_dir="$HOME/.claude"
claude_settings="$claude_config_dir/settings.json"
mkdir -p "$claude_config_dir"
printf '%s\n' '{"env":{"CLAUDE_AFK_TIMEOUT_MS":"86400000","CLAUDE_CODE_DISABLE_CRON":"1","CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY":"1"},"sandbox":{"enabled":false,"allowUnsandboxedCommands":true},"defaultMode":"bypassPermissions","skipDangerousModePermissionPrompt":true}' > "$claude_settings"
chmod 600 "$claude_settings"
"#;

/// Positional-argument parse the workspace script runs between the guards
/// and the cache validation; the plain nix-setup script has none.
const GUEST_WORKSPACE_POSITIONAL: &str = r#"repo="$1"
destination="$2"
warm="$3"
shift 3

"#;

/// Shared by BOTH guest scripts: wait for the broker, then run the
/// egress-isolation gate, routing a failure through the daemon-polled
/// bootstrap-failed sentinel (both scripts surface failures identically). Runs
/// in the trusted window — after broker-ready, before any repo/agent/guest
/// command — so on failure neither workload starts.
///
/// Adversarially confirm the no-egress invariant: the guest must reach the
/// broker (positive control — proves the probe itself works, so a failed
/// external probe means isolation, not a broken probe) and must NOT reach the
/// public internet (negative control). Any external TCP connect that SUCCEEDS,
/// any global-scope IPv6 address (a SLAAC'd ULA from a host RA included; see
/// #218), or an unreachable broker aborts. Pure bash /dev/tcp + coreutils
/// timeout + iproute2; raw IPs, so it probes L3/L4 egress without DNS.
const GUEST_BROKER_READY_AND_EGRESS_GATE: &str = r#"
while [ ! -f /run/writ-agent-vm/broker-ready ]; do
  sleep 0.2
done

egress_gate() {
  _auth="${WRIT_NIX_CACHE_URL#*://}"
  _hostport="${_auth%%/*}"
  _bhost="${_hostport%%:*}"
  case "$_hostport" in
    *:*) _bport="${_hostport##*:}" ;;
    *) _bport=80 ;;
  esac
  # rc 0 iff a TCP connection is established within $1 seconds. The host/port
  # are passed as the inner bash's $1/$2 (after the _ argv0); the bash -c body
  # is single-quoted, so they expand in the INNER bash, never the caller.
  _connect() { timeout "$1" bash -c ': <"/dev/tcp/$1/$2"' _ "$2" "$3" 2>/dev/null; }
  # rc 0 iff the resolver at $1 ANSWERS a UDP DNS query within 2s — i.e. port-53
  # egress is open. A minimal A-query for example.com; `read -n 1` returns on the
  # first reply byte (a binary DNS reply has no newline, so `read -r` would hang
  # past the answer). UDP send is fire-and-forget, so only a reply is evidence.
  # The socket is a redirect on the command GROUP, never `exec` — a failed
  # `exec` redirect is FATAL, so an unreachable resolver (the isolated case)
  # would abort the whole gate; here it is just a non-zero "no answer".
  _dns_answers() {
    # 2>/dev/null BEFORE 3<> so a failed open (unreachable resolver) is silent,
    # not just non-fatal — redirects apply left to right.
    {
      printf '\xfe\xed\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' >&3
      read -t 2 -n 1 _ <&3
    } 2>/dev/null 3<>"/dev/udp/$1/53"
  }
  # Positive control: the broker must be reachable, else a failed external probe
  # cannot be attributed to isolation. broker-ready was just signalled, but
  # tolerate a slow first accept with a short retry — a false abort here would
  # refuse a perfectly isolated VM. Generous per-try timeout for the same
  # reason.
  _n=0
  until _connect 5 "$_bhost" "$_bport"; do
    _n=$((_n + 1))
    if [ "$_n" -ge 5 ]; then
      echo "egress gate: broker $_bhost:$_bport unreachable after $_n tries; cannot validate egress isolation" >&2
      return 1
    fi
    sleep 0.5
  done
  # Negative control: the public internet must be unreachable. A handshake to a
  # reachable host completes in well under 2s on this path; a blocked one never
  # completes (a firewall that drops rather than rejects makes connect hang), so
  # a tight 2s bounds the per-probe boot cost. Raw IPs avoid any DNS dependency.
  for _t in 1.1.1.1:443 8.8.8.8:443; do
    if _connect 2 "${_t%%:*}" "${_t##*:}"; then
      echo "egress gate: LEAK — connected to ${_t} from the guest; refusing to run the agent" >&2
      return 1
    fi
  done
  # Also confirm no external DNS egress: a firewall that allows port 53 ("for
  # name resolution") leaks even when 443 is blocked, so probe a public resolver
  # directly. A reply is a leak.
  if _dns_answers 1.1.1.1; then
    echo "egress gate: LEAK — external DNS resolver 1.1.1.1 answered a query; refusing to run the agent" >&2
    return 1
  fi
  # No global-scope IPv6 — but only in the no-guest-IPv6 lifecycle mode. The
  # daemon sets WRIT_EGRESS_GATE_REQUIRE_NO_IPV6=1 there and =0 for the
  # dual-stack mode, which provisions a ULA on purpose; a missing value defaults
  # to "do not enforce" so this never breaks a mode it was not told to police.
  if [ "${WRIT_EGRESS_GATE_REQUIRE_NO_IPV6:-0}" = 1 ]; then
    # Fail closed if the probe cannot RUN (ip missing / errors): an empty result
    # must mean "ip ran and found no global address", never "ip could not be
    # asked". A query that finds nothing still exits 0, so a non-zero status
    # here is an inability to validate, which aborts.
    if ! _v6="$(ip -6 addr show scope global 2>/dev/null)"; then
      echo "egress gate: could not run 'ip -6 addr' to validate IPv6 posture; refusing to run the agent" >&2
      return 1
    fi
    if [ -n "$_v6" ]; then
      echo "egress gate: guest holds a global-scope IPv6 address; refusing to run the agent" >&2
      echo "$_v6" >&2
      return 1
    fi
  fi
  return 0
}

# Run the gate; on failure route the reason through the daemon-polled
# bootstrap-failed sentinel and stay alive so the daemon reads it before
# teardown. Shared by both scripts (the daemon waits on the same sentinels for
# both), so every session surfaces a gate failure identically rather than
# returning a "started" VM that the gate then kills.
if ! egress_gate 2>/run/writ-agent-vm/egress-gate.stderr; then
  set +e
  {
    printf 'egress isolation gate failed; refusing to run the guest command\n'
    cat /run/writ-agent-vm/egress-gate.stderr
  } > /run/writ-agent-vm/bootstrap-failed
  set -e
  while :; do sleep 3600; done
fi
rm -f /run/writ-agent-vm/egress-gate.stderr
"#;

/// Tail of the plain nix-setup script: the egress gate has passed (shared
/// fragment above), so signal bootstrap-ok and run the guest command as a
/// CHILD, then loop — exactly the workspace script's agent-run shape. Running
/// the command as a child (not `exec`) keeps the container alive past it, so
/// the daemon reliably observes bootstrap-ok even for a fast command, and a
/// gate failure is surfaced through bootstrap-failed rather than a silently
/// dead VM. The daemon owns teardown via the stop API.
const GUEST_NIX_SETUP_TAIL: &str = r#"
touch /run/writ-agent-vm/bootstrap-ok
set +e
"$@"
set -e
while :; do sleep 3600; done
"#;

/// Tail of the workspace script: the egress gate has passed (shared fragment
/// above); run the workspace init, then the agent as a child so the container
/// outlives it.
const GUEST_WORKSPACE_BOOTSTRAP_TAIL: &str = r#"
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

/// The shared nix prologue — env guards, positional parse, cache-host
/// derivation, the netrc credential write, and the nix.conf block — up to (but
/// not including) the egress gate. Factored out so a test can exercise the
/// nix.conf generation on its own: the full scripts cannot run on the build
/// host (the gate needs a container, `timeout`, and a no-egress network).
fn nix_conf_prologue(positional: &str, mkdir_line: &str, features_line: &str) -> String {
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
    script.push_str(GUEST_CLAUDE_SETTINGS);
    script
}

/// A host-runnable script that exercises exactly the shared nix.conf prologue
/// (no `/run` mkdir, no gate, no `broker-ready` wait), then execs the command.
/// The two nix.conf-generation tests use this; the real scripts cannot run on
/// the build host because the gate requires the guest container environment.
#[cfg(test)]
pub(super) fn nix_conf_prologue_script_for_test() -> String {
    let mut script = nix_conf_prologue(
        "",
        r#"mkdir -p "$netrc_dir" "$NIX_CONF_DIR""#,
        r#"  printf 'experimental-features = nix-command\n'"#,
    );
    script.push_str("\nexec \"$@\"\n");
    script
}

/// Assemble a guest setup script from the shared nix prologue, the egress gate
/// (shared by both scripts), and the per-script `tail`. See [`nix_setup_script`]
/// and [`workspace_bootstrap_script`].
fn build_guest_nix_setup_script(
    positional: &str,
    mkdir_line: &str,
    features_line: &str,
    tail: &str,
) -> String {
    let mut script = nix_conf_prologue(positional, mkdir_line, features_line);
    // Both scripts gate on egress isolation in the same trusted window, with
    // identical failure handling, so the broker-ready wait + gate + its
    // bootstrap-failed routing are shared here; each tail picks up after a
    // passed gate.
    script.push_str(GUEST_BROKER_READY_AND_EGRESS_GATE);
    script.push_str(tail);
    script
}

/// The non-workspace guest setup script: configure the nix cache, run the
/// egress gate, then `exec` the wrapped guest command. Does not enable flakes.
/// Creates the `/run/writ-agent-vm` runtime dir the gate and the broker-ready
/// signal need.
pub(super) fn nix_setup_script() -> String {
    build_guest_nix_setup_script(
        "",
        r#"mkdir -p "$netrc_dir" "$NIX_CONF_DIR" /run/writ-agent-vm"#,
        r#"  printf 'experimental-features = nix-command\n'"#,
        GUEST_NIX_SETUP_TAIL,
    )
}

/// The workspace guest setup script: the shared nix prologue (with flakes
/// and the `/run/writ-agent-vm` runtime dir), the egress gate, the workspace
/// init, then the agent run.
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
