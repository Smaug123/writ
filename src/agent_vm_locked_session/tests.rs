//! Tests for the daemon's interpreter of the locked start sequence.
//!
//! One oracle, from Stage E2 of
//! `docs/plans/2026-09-01-ipv4-only-locked-v1.md`: against a fake `container`
//! and a fake PF helper, a locked start runs its steps in order and ends with
//! the record at `WorkloadReleased`; and every way a step can fail leaves the
//! session at the phase it reached, with the workload unreleased — no `kill`
//! in the tool's log at all.
//!
//! The sharpest assertion is the ordering one: the fake `kill` reads the
//! session's record off disk as it runs, so "recorded before sent" is checked
//! by the thing being released rather than inferred from the code.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;
use crate::agent_vm_lifecycle::{
    AgentVmGuestEnvVar, AgentVmResources, BrokerPlacement, ContainerImage, Ipv6IsolationMode,
};
use crate::agent_vm_locked_lifecycle::LockedPhase;
use crate::agent_vm_pf_helper_protocol::{PF_HELPER_PROTOCOL_NAME, PF_HELPER_PROTOCOL_VERSION};
use crate::core::{
    AgentNetworkPool, BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId,
};
use crate::test_support::{shell_quote_path, write_executable_script};
use std::net::{Ipv4Addr, Ipv6Addr};
use writ_guest_init::record::SECURITY_READY_LINE;

const IMAGE_DIGEST: &str =
    "sha256:226205c93c1bc4148f691c0162118b39d8fca907691e9fc620bddce2dec6567e";
const OTHER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn session_id() -> SessionId {
    SessionId::from_uuid(uuid::Uuid::from_u128(
        0x51b8_fd0f_6c10_454c_b0e6_7df1_d60e_2e6d,
    ))
}

fn admitted() -> ImageDigest {
    ImageDigest::parse(IMAGE_DIGEST).unwrap()
}

/// What the readback sees: a container matching the locked launch.
fn inspect_doc(digest: &str) -> String {
    json!([{
        "configuration": {
            "image": {"descriptor": {"digest": digest}, "reference": "writ-agent-vm-guest:latest"},
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

/// What the PF helper's install reports: the anchor, the interfaces it
/// resolved, and the phase it completed.
///
/// Written out field by field, in the order the wire struct declares them,
/// because the helper's parser accepts only a document that re-renders to
/// exactly the bytes it was given. `the_fixture_report_is_one_the_helper_could_have_printed`
/// holds this to that parser, so a fixture that drifts fails there rather
/// than making every test here fail for the wrong reason.
fn install_report(phase: &str) -> String {
    format!(
        r#"{{"protocol":"{PF_HELPER_PROTOCOL_NAME}","version":{PF_HELPER_PROTOCOL_VERSION},"anchor":"writ/session/{session}","interfaces":["bridge100","vmenet0"],"phase":"{phase}"}}"#,
        session = session_id(),
    )
}

/// The fixture is a document the real helper could have printed, checked by
/// the real parser.
#[test]
fn the_fixture_report_is_one_the_helper_could_have_printed() {
    let doc = PfHelperInstallReportDoc::parse(&install_report("reresolve"))
        .expect("the fixture parses as an install report");
    assert_eq!(doc.phase(), PfInstallPhase::Reresolve);
    assert_eq!(doc.interfaces().len(), 2);
    assert_eq!(doc.session_id(), session_id());
}

/// How the fake tools misbehave, if at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Fault {
    None,
    CreateFails,
    /// The created VM is a different image from the admitted one.
    WrongImage,
    StartFails,
    /// The helper's install stops before it has re-resolved the interfaces.
    FirewallIncomplete,
    /// The guest never publishes `security-ready`.
    GuestSilent,
    /// The guest reports that its handoff failed.
    GuestHandoffFailed,
    KillFails,
    /// The `kill` succeeds and the session's record then vanishes, so the
    /// write that would have recorded the release fails.
    StateLostAfterKill,
    /// The privileged install takes its time before reporting.
    FirewallSlow,
    FirewallFails,
    /// The install floods its output instead of reporting.
    FirewallFloods,
}

struct Harness {
    dir: tempfile::TempDir,
    store: AgentVmSessionStateStore,
    plan: AgentVmSessionPlan,
    tools: AgentVmToolPaths,
}

impl Harness {
    fn new(fault: Fault) -> Self {
        Self::with_guest_env(fault, Vec::new())
    }

    fn with_guest_env(fault: Fault, guest_env: Vec<AgentVmGuestEnvVar>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("inspect.json"), inspect_doc(IMAGE_DIGEST)).unwrap();
        fs::write(root.join("inspect-wrong.json"), inspect_doc(OTHER_DIGEST)).unwrap();
        fs::write(root.join("report.json"), install_report("reresolve")).unwrap();
        fs::write(root.join("report-short.json"), install_report("load")).unwrap();
        fs::write(root.join("ready.txt"), format!("{SECURITY_READY_LINE}\n")).unwrap();
        fs::write(
            root.join("failed.txt"),
            "writ-agent-vm-guest-init handoff-failed step=5 reason=bounding set survived\n",
        )
        .unwrap();

        let container = write_executable_script(
            root,
            "container",
            &format!(
                r#"#!/bin/sh
root="{root}"
printf '%s\n' "$*" >> "$root/argv.log"
case "$1" in
  create)
    # Copy the env file while the create can still see it, so a test can
    # assert it existed and what was in it.
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--env-file" ]; then cp "$2" "$root/env-at-create"; fi
      shift
    done
    [ "{fault:?}" = CreateFails ] && exit 3
    exit 0 ;;
  inspect)
    if [ "{fault:?}" = WrongImage ]; then cat "$root/inspect-wrong.json"; else cat "$root/inspect.json"; fi
    exit 0 ;;
  start) [ "{fault:?}" = StartFails ] && exit 4; exit 0 ;;
  logs)
    case "{fault:?}" in
      GuestSilent) printf 'still booting\n' ;;
      GuestHandoffFailed) cat "$root/failed.txt" ;;
      *) cat "$root/ready.txt" ;;
    esac
    exit 0 ;;
  kill)
    cp "$root/state/{session}.json" "$root/record-at-kill.json" 2>/dev/null
    [ "{fault:?}" = StateLostAfterKill ] && rm -f "$root/state/{session}.json"
    [ "{fault:?}" = KillFails ] && exit 5
    exit 0 ;;
esac
printf 'unexpected argv: %s\n' "$*" >&2
exit 64
"#,
                root = root.display(),
                fault = fault,
                session = session_id(),
            ),
        );
        let helper = write_executable_script(
            root,
            "pf-helper",
            &format!(
                r#"#!/bin/sh
printf 'helper %s\n' "$*" >> {log}
case "{fault:?}" in
  FirewallIncomplete) cat "{root}/report-short.json" ;;
  FirewallSlow) sleep 3; cat "{root}/report.json" ;;
  FirewallFails) printf 'the helper failed\n' >&2; exit 7 ;;
  FirewallFloods) exec head -c 200000 /dev/zero ;;
  *) cat "{root}/report.json" ;;
esac
exit 0
"#,
                log = shell_quote_path(&root.join("argv.log")),
                root = root.display(),
                fault = fault,
            ),
        );
        // `sudo` runs whatever it is given, as the real one would.
        let sudo = write_executable_script(root, "sudo", "#!/bin/sh\nexec \"$@\"\n");

        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let tools = AgentVmToolPaths::new(&container, &helper, &sudo);
        let plan = AgentVmSessionPlan::new_with_guest_env(
            session_id(),
            AgentNetworkPool::new(
                Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                Ipv6Cidr::new(Ipv6Addr::from(0xfd83_b6f2_0e57u128 << 80), 48).unwrap(),
            )
            .unwrap(),
            7,
            BrokerPorts::new([BrokerPort::new(51375).unwrap()]).unwrap(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            Ipv6IsolationMode::Ipv4OnlyLockedV1,
            BrokerPlacement::Host,
            ContainerImage::new("writ-agent-vm-guest:latest").unwrap(),
            guest_env,
            vec!["sleep".into(), "600".into()],
            AgentVmResources::new(1, 512).unwrap(),
            tools.clone(),
        )
        .unwrap();
        Self {
            store: AgentVmSessionStateStore::new(state_dir),
            dir,
            plan,
            tools,
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Claim the record, then run the locked start against it.
    ///
    /// The guest channel gets bounds a test can sit through; every other
    /// bound stays the production one, because nothing here waits them out.
    async fn run(&self) -> Result<AgentVmSessionState, LockedStartError> {
        let claimed = self.store.create_starting(&self.plan).unwrap();
        let channel = GuestLogChannel::new(self.tools.container(), self.plan.names().vm())
            .with_wait_bounds_for_test(Duration::from_millis(5), Duration::from_secs(3));
        run_locked_start(
            &self.store,
            &self.plan,
            &self.tools,
            claimed,
            &admitted(),
            &channel,
        )
        .await
    }

    fn argv_lines(&self) -> Vec<String> {
        fs::read_to_string(self.root().join("argv.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The first word of each recorded invocation, in order.
    fn steps(&self) -> Vec<String> {
        self.argv_lines()
            .iter()
            .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
            .collect()
    }

    fn phase(&self) -> Option<LockedPhase> {
        self.store.load(session_id()).unwrap().locked_phase()
    }

    fn record_seen_by_kill(&self) -> Option<PathBuf> {
        let path = self.root().join("record-at-kill.json");
        path.exists().then_some(path)
    }
}

/// A claimed locked session starts at `Claimed`, which is what makes every
/// later phase reachable: `advance_locked` refuses a record that is not
/// already locked.
#[test]
fn a_locked_plan_claims_a_locked_record() {
    let harness = Harness::new(Fault::None);
    let claimed = harness.store.create_starting(&harness.plan).unwrap();
    assert_eq!(claimed.locked_phase(), Some(LockedPhase::Claimed));
}

#[tokio::test]
async fn a_locked_start_runs_its_steps_in_order_and_releases() {
    let harness = Harness::new(Fault::None);
    let state = harness.run().await.expect("the locked start completes");
    assert_eq!(state.locked_phase(), Some(LockedPhase::WorkloadReleased));
    assert_eq!(
        harness.steps(),
        vec!["create", "inspect", "start", "helper", "logs", "kill"]
    );
}

/// The record says `ReleaseAttempted` *before* the signal is sent, checked by
/// the fake `kill` reading the record as it runs. This is the ordering Stage
/// E1 made structural, so it is asserted against the thing being released
/// rather than against the code that releases it.
#[tokio::test]
async fn the_release_is_recorded_before_the_signal_is_sent() {
    let harness = Harness::new(Fault::None);
    harness.run().await.unwrap();
    let seen = harness
        .record_seen_by_kill()
        .expect("the kill ran and copied the record");
    let recorded = fs::read_to_string(seen).unwrap();
    assert!(
        recorded.contains("release_attempted"),
        "the record at kill time should already say release_attempted: {recorded}"
    );
}

/// Every failure before the release leaves the workload unreleased, and the
/// phase says how far the start got. The `kill` is the thing that must not
/// have happened, so it is asserted absent from the tool's own log.
#[tokio::test]
async fn every_failure_before_the_release_leaves_the_workload_unreleased() {
    let cases = [
        (Fault::CreateFails, Some(LockedPhase::NetworkValidated)),
        (Fault::WrongImage, Some(LockedPhase::NetworkValidated)),
        (Fault::StartFails, Some(LockedPhase::NetworkValidated)),
        (Fault::FirewallIncomplete, Some(LockedPhase::AgentVmStarted)),
        (
            Fault::GuestSilent,
            Some(LockedPhase::FinalFirewallInstalled),
        ),
        (
            Fault::GuestHandoffFailed,
            Some(LockedPhase::FinalFirewallInstalled),
        ),
    ];
    for (fault, expected) in cases {
        let harness = Harness::new(fault);
        let error = harness.run().await.expect_err("the start should fail");
        assert!(
            !error.workload_may_be_running(),
            "{fault:?} failed before the release, so the workload cannot be running: {error}"
        );
        assert_eq!(harness.phase(), expected, "{fault:?}");
        assert!(
            !harness.steps().contains(&"kill".to_string()),
            "{fault:?} must not have signalled the guest: {:?}",
            harness.steps()
        );
    }
}

/// A readback that refuses stops before the VM is ever started — which is the
/// whole reason the launch creates and verifies before starting.
#[tokio::test]
async fn a_refused_readback_stops_before_the_vm_is_started() {
    let harness = Harness::new(Fault::WrongImage);
    let error = harness.run().await.unwrap_err();
    assert!(
        matches!(error, LockedStartError::ShapeMismatch(_)),
        "{error}"
    );
    assert_eq!(harness.steps(), vec!["create", "inspect"]);
}

/// A `kill` that fails is not a workload that stayed put: the record already
/// says `ReleaseAttempted`, and the daemon cannot tell a lost report from a
/// lost signal. So the phase stays at `ReleaseAttempted` and the error says
/// the workload may be running.
#[tokio::test]
async fn a_failed_kill_leaves_the_session_answerable_rather_than_resolved() {
    let harness = Harness::new(Fault::KillFails);
    let error = harness.run().await.unwrap_err();
    assert!(
        error.workload_may_be_running(),
        "a failed kill does not prove non-delivery: {error}"
    );
    assert_eq!(harness.phase(), Some(LockedPhase::ReleaseAttempted));
}

/// A locked session's configured guest environment reaches the VM.
///
/// The daemon supplies broker credentials and Nix settings this way, and the
/// guest bootstrap needs them — a create with no `--env-file` would start a
/// VM that cannot reach its own broker. The fake copies the file while the
/// create can still see it, so this asserts the file *existed at create
/// time*, not merely that a path was named.
#[tokio::test]
async fn the_configured_guest_environment_reaches_the_create() {
    let harness = Harness::with_guest_env(
        Fault::None,
        vec![AgentVmGuestEnvVar::new("WRIT_BROKER_URL", "http://10.0.0.1:51375").unwrap()],
    );
    harness.run().await.unwrap();
    let copied = fs::read_to_string(harness.root().join("env-at-create"))
        .expect("the create was given an env file that existed when it ran");
    assert_eq!(copied.trim(), "WRIT_BROKER_URL=http://10.0.0.1:51375");
    // And the file is not left behind once the create has read it.
    let named = harness
        .argv_lines()
        .iter()
        .find(|line| line.starts_with("create "))
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            while let Some(part) = parts.next() {
                if part == "--env-file" {
                    return parts.next().map(str::to_string);
                }
            }
            None
        })
        .expect("the create names an env file");
    assert!(
        !Path::new(&named).exists(),
        "the env file should be gone once the create has read it: {named}"
    );
}

/// A session with no configured environment names no env file, rather than
/// an empty one.
#[tokio::test]
async fn a_session_with_no_guest_environment_names_no_env_file() {
    let harness = Harness::new(Fault::None);
    harness.run().await.unwrap();
    assert!(
        !harness
            .argv_lines()
            .iter()
            .any(|line| line.contains("--env-file")),
        "{:?}",
        harness.argv_lines()
    );
}

/// A record that cannot be written *after* a successful `kill` describes a
/// workload that is running, not one that stayed put.
///
/// The phase on disk already says `ReleaseAttempted`, which is the phase that
/// means exactly this; the error has to agree, because a caller that read it
/// as "never released" would tear the session down believing the guest was
/// still parked. Injected by the `kill` itself removing the record, so the
/// failure lands after a signal that really was delivered.
#[tokio::test]
async fn a_write_that_fails_after_the_kill_says_the_workload_may_be_running() {
    let harness = Harness::new(Fault::StateLostAfterKill);
    let error = harness.run().await.unwrap_err();
    assert!(
        matches!(error, LockedStartError::ReleasedButNotRecorded { .. }),
        "{error}"
    );
    assert!(
        error.workload_may_be_running(),
        "a write that failed after the kill must not read as unreleased: {error}"
    );
    // The kill ran, and the record it saw already said the release was
    // attempted — which is what makes the session answerable at all.
    let seen = fs::read_to_string(harness.record_seen_by_kill().expect("the kill ran")).unwrap();
    assert!(seen.contains("release_attempted"), "{seen}");
}

/// The privileged install is waited for, however long it takes.
///
/// Every other step here stops *waiting* at a deadline, which is harmless for
/// a read: the fact is simply unread. An install is different. `run_bounded_probe`
/// cannot kill the root half behind `sudo`, so abandoning a running install
/// would let the daemon move on to teardown, flush the anchor, and have the
/// helper load its rules afterwards — leaving an anchor behind for a session
/// that no longer exists.
///
/// The helper here takes three seconds. The assertion is that it still
/// succeeds, which fails the moment anyone reintroduces a deadline shorter
/// than that.
#[tokio::test]
async fn a_slow_privileged_install_is_waited_for_rather_than_abandoned() {
    let harness = Harness::new(Fault::FirewallSlow);
    let state = harness.run().await.expect("the slow install is waited for");
    assert_eq!(state.locked_phase(), Some(LockedPhase::WorkloadReleased));
}

/// An install that fails is refused, and the guest is not released.
#[tokio::test]
async fn an_install_that_fails_does_not_release_the_guest() {
    let harness = Harness::new(Fault::FirewallFails);
    let error = harness.run().await.unwrap_err();
    assert!(
        matches!(error, LockedStartError::FirewallReportUnreadable(_)),
        "{error}"
    );
    assert!(!harness.steps().contains(&"kill".to_string()));
}

/// An install that floods is refused rather than read in part: a report cut
/// off at the cap could be missing the phase that says it did not finish.
#[tokio::test]
async fn an_install_that_floods_is_refused_rather_than_read_in_part() {
    let harness = Harness::new(Fault::FirewallFloods);
    let error = harness.run().await.unwrap_err();
    assert!(
        matches!(error, LockedStartError::FirewallReportUnreadable(_)),
        "{error}"
    );
    assert_eq!(harness.phase(), Some(LockedPhase::AgentVmStarted));
    assert!(!harness.steps().contains(&"kill".to_string()));
}
