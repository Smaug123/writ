//! Tests for the locked profile's `container run` and its readback.
//!
//! Two oracles, from Stage E2 of
//! `docs/plans/2026-09-01-ipv4-only-locked-v1.md`:
//!
//! 1. The launch argv carries exactly Stage B1's capability profile, relaxes
//!    exactly `/proc/sys`, names the initializer as the container command, and
//!    shares its base with the legacy launch so a change to the session's
//!    identity or resources reaches both.
//! 2. The readback accepts a container matching that launch and refuses every
//!    single-field departure from it, over a document captured from the real
//!    `container inspect`.

use proptest::prelude::*;
use serde_json::{Value, json};

use std::path::Path;

use super::*;
use crate::agent_vm_lifecycle::AgentVmSessionPlan;
use crate::agent_vm_lifecycle::test_support::plan;
use writ_guest_init::capability_argv::{
    LOCKED_CAPABILITY_ARGV_PROFILE, parse_locked_capability_argv_profile,
};

/// The image and guest command the shared lifecycle fixture builds a plan
/// around.
const TEST_IMAGE: &str = "alpine:latest";
const TEST_GUEST_COMMAND: [&str; 2] = ["sleep", "600"];

fn test_plan() -> AgentVmSessionPlan {
    plan(7)
}

/// A real `container inspect` document, captured from Apple `container` 1.4.1
/// against a container started with the locked capability profile and
/// `--read-only-path` set. The fixture is the tool's own output rather than a
/// hand-written approximation, so a parser that only works on what we imagined
/// the tool prints fails here.
///
/// It was captured with a stand-in image and `/bin/sleep` as the command,
/// because capturing it from the guest image would have meant running the
/// handoff; the fields under test are the runtime's, and the tests set their
/// values themselves.
const REAL_INSPECT: &str = include_str!("container-inspect.json");

const ADMITTED_DIGEST: &str =
    "sha256:226205c93c1bc4148f691c0162118b39d8fca907691e9fc620bddce2dec6567e";
const OTHER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn admitted() -> ImageDigest {
    ImageDigest::parse(ADMITTED_DIGEST).unwrap()
}

/// The captured document with the fields the locked launch would produce, and
/// `mutate` applied on top.
fn inspect_doc(mutate: impl FnOnce(&mut Value)) -> String {
    let mut doc: Value = serde_json::from_str(REAL_INSPECT).unwrap();
    let configuration = &mut doc[0]["configuration"];
    configuration["image"]["descriptor"]["digest"] = json!(ADMITTED_DIGEST);
    configuration["initProcess"]["executable"] = json!(GUEST_INIT_PATH);
    mutate(configuration);
    serde_json::to_string(&doc).unwrap()
}

fn shape(mutate: impl FnOnce(&mut Value)) -> LockedContainerShape {
    LockedContainerShape::parse(&inspect_doc(mutate)).expect("fixture parses")
}

// --- the launch argv --------------------------------------------------------

fn locked_argv(plan: &AgentVmSessionPlan) -> Vec<String> {
    plan.locked_create_vm_invocation(None).args_lossy()
}

/// The index of the one contiguous occurrence of `needle` in `haystack`.
fn sole_window(haystack: &[String], needle: &[&str]) -> usize {
    let found: Vec<usize> = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| window.iter().zip(needle).all(|(a, b)| a == b))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one {needle:?} in {haystack:?}"
    );
    found[0]
}

/// The capability arguments are Stage B1's profile, in one run, and B1's own
/// parser accepts that slice — so the launch cannot drift from the set the
/// design lists without failing B1's parser too.
#[test]
fn the_locked_launch_carries_stage_b1s_capability_profile_exactly() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    let at = sole_window(&argv, &LOCKED_CAPABILITY_ARGV_PROFILE);
    let slice = &argv[at..at + LOCKED_CAPABILITY_ARGV_PROFILE.len()];
    parse_locked_capability_argv_profile(slice).expect("B1 accepts the launch's capability argv");
}

/// The launch clears the runtime's read-only defaults and gives every one of
/// them back except `/proc/sys`, which is the only path the handoff needs to
/// write.
#[test]
fn the_locked_launch_relaxes_only_proc_sys() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    let given_back: Vec<&str> = argv
        .windows(2)
        .filter(|pair| pair[0] == "--read-only-path" && pair[1] != "NONE")
        .map(|pair| pair[1].as_str())
        .collect();
    assert_eq!(given_back, LOCKED_KEPT_READONLY_PATHS);
    assert!(
        !given_back.contains(&"/proc/sys"),
        "/proc/sys must be the relaxation, not one of the paths given back"
    );
    // `NONE` has to come first: `--read-only-path` is additive otherwise, so a
    // `NONE` after the paths would clear the very ones being given back.
    let none_at = sole_window(&argv, &["--read-only-path", "NONE"]);
    let first_kept = sole_window(&argv, &["--read-only-path", LOCKED_KEPT_READONLY_PATHS[0]]);
    assert!(none_at < first_kept);
}

/// The initializer is the *container command*, immediately after the image,
/// with the guest command behind it — so the image's own entrypoint is
/// untouched and the legacy profile's launch of the same image is unchanged.
#[test]
fn the_locked_launch_names_the_initializer_as_the_container_command() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    let image_at = argv
        .iter()
        .position(|arg| arg == TEST_IMAGE)
        .expect("the image is named");
    assert_eq!(argv[image_at + 1], GUEST_INIT_PATH);
    assert_eq!(
        &argv[image_at + 2..],
        TEST_GUEST_COMMAND.map(str::to_string)
    );
}

/// The locked launch creates without starting, and starts as a separate step.
///
/// This is the whole of the readback's value: `create` resolves the tag and
/// records the resolved digest while the container is still `stopped`, so a
/// tag repointed between admission and launch is rejected before its PID 1
/// has run. A `container run` would have executed it first.
#[test]
fn the_locked_launch_creates_without_starting() {
    let plan = test_plan();
    let create = locked_argv(&plan);
    assert_eq!(create.first().map(String::as_str), Some("create"));
    assert!(
        !create.iter().any(|arg| arg == "-d" || arg == "--detach"),
        "create starts nothing to detach from: {create:?}"
    );

    let start = plan.locked_start_vm_invocation().args_lossy();
    assert_eq!(
        start,
        vec!["start".to_string(), plan.names().vm().to_string()]
    );
    assert!(
        !start.iter().any(|arg| arg == "--attach" || arg == "-a"),
        "attaching would hold the daemon to the guest's streams: {start:?}"
    );
}

/// The image is named by tag, not digest: Apple `container` resolves a
/// `name@sha256:…` reference against the registry, and the guest image is
/// local. The digest is checked by reading the started VM back instead.
#[test]
fn the_locked_launch_names_the_image_by_tag() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    assert!(argv.contains(&TEST_IMAGE.to_string()));
    assert!(
        !argv.iter().any(|arg| arg.contains("@sha256:")),
        "a digest reference would not resolve for a local image: {argv:?}"
    );
}

/// No `--kernel-arg ipv6.disable=1`. The legacy profile's kernel-line disable
/// removes `/proc/sys/net/ipv6` entirely, and the Stage B1 handoff requires
/// `disable_ipv6` to *exist* — `Ipv6Sysctl::must_exist` makes a missing one a
/// handoff failure. The two enforcements are mutually exclusive, and the
/// locked profile takes the one whose completion it can observe.
#[test]
fn the_locked_launch_does_not_disable_ipv6_on_the_kernel_line() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    assert!(
        !argv.iter().any(|arg| arg == "--kernel-arg"),
        "a kernel-line IPv6 disable would remove the sysctl the handoff must write: {argv:?}"
    );
}

/// The locked launch carries the session's identity and per-session state.
///
/// It gets these by calling the same `base_run_argv` the legacy launch does,
/// so "the two agree" is a fact about the code rather than something to
/// assert; what is worth asserting is that the base is *there*, because a
/// locked launch assembled without it would start an unnamed VM on the
/// default network.
#[test]
fn the_locked_launch_carries_the_sessions_identity_and_state() {
    let plan = test_plan();
    let argv = locked_argv(&plan);
    let names = plan.names();
    sole_window(&argv, &["--name", names.vm()]);
    sole_window(&argv, &["--network", names.network()]);
    for mount in ["/tmp", "/run", "/var/tmp", "/root"] {
        sole_window(&argv, &["--tmpfs", mount]);
    }
    assert_eq!(argv.first().map(String::as_str), Some("create"));
}

/// An env file is passed before the image, where `container run` expects its
/// options.
#[test]
fn the_locked_launch_puts_the_env_file_among_the_options() {
    let plan = test_plan();
    let argv = plan
        .locked_create_vm_invocation(Some(Path::new("/tmp/env")))
        .args_lossy();
    let env_at = sole_window(&argv, &["--env-file", "/tmp/env"]);
    let image_at = argv.iter().position(|arg| arg == TEST_IMAGE).unwrap();
    assert!(env_at < image_at);
}

// --- the readback -----------------------------------------------------------

/// The captured document parses, and the fields the readback depends on are
/// the ones the real tool emits.
#[test]
fn the_captured_inspect_document_parses() {
    let parsed = LockedContainerShape::parse(REAL_INSPECT).expect("the real document parses");
    assert_eq!(parsed.image_reference(), "docker.io/library/alpine:latest");
    assert_eq!(
        parsed.image_digest().as_str(),
        "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
    );
}

/// A container that matches the launch verifies against the admitted digest.
#[test]
fn a_container_matching_the_launch_verifies() {
    shape(|_| {})
        .verify(&admitted())
        .expect("the locked shape verifies");
}

/// `container inspect` spells a capability with a `CAP_` prefix that
/// `--cap-add` does not, so the readback converts rather than comparing what
/// it sent. Stated over every capability, because a set compared in the wrong
/// spelling would be empty-vs-full rather than subtly wrong.
#[test]
fn the_inspect_spelling_is_the_argv_spelling_with_a_prefix() {
    for capability in TemporaryCapability::ALL {
        let argv_name = capability.container_name();
        let inspect_name = inspect_capability_name(capability);
        assert_eq!(inspect_name, format!("CAP_{argv_name}"));
        assert_ne!(inspect_name, argv_name);
    }
}

/// One way a running container can depart from the launch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Departure {
    WrongImage,
    ExtraCapability,
    MissingCapability,
    ArgvSpelledCapabilities,
    DroppingNothing,
    ProcSysGivenBack,
    NothingReadOnly,
    WrongInitExecutable,
    InitIsTheLockedIdentity,
    RuntimeInitInterposed,
}

impl Departure {
    const ALL: [Self; 10] = [
        Self::WrongImage,
        Self::ExtraCapability,
        Self::MissingCapability,
        Self::ArgvSpelledCapabilities,
        Self::DroppingNothing,
        Self::ProcSysGivenBack,
        Self::NothingReadOnly,
        Self::WrongInitExecutable,
        Self::InitIsTheLockedIdentity,
        Self::RuntimeInitInterposed,
    ];

    fn apply(self, configuration: &mut Value) {
        match self {
            Self::WrongImage => {
                configuration["image"]["descriptor"]["digest"] = json!(OTHER_DIGEST)
            }
            Self::ExtraCapability => {
                configuration["capAdd"] = json!([
                    "CAP_CHOWN",
                    "CAP_SETGID",
                    "CAP_SETUID",
                    "CAP_SETPCAP",
                    "CAP_NET_ADMIN",
                    "CAP_NET_RAW"
                ])
            }
            Self::MissingCapability => {
                configuration["capAdd"] = json!(["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"])
            }
            Self::ArgvSpelledCapabilities => {
                configuration["capAdd"] =
                    json!(["CHOWN", "SETGID", "SETUID", "SETPCAP", "NET_ADMIN"])
            }
            Self::DroppingNothing => configuration["capDrop"] = json!([]),
            Self::ProcSysGivenBack => {
                configuration["readonlyPaths"] =
                    json!(["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys"])
            }
            Self::NothingReadOnly => configuration["readonlyPaths"] = json!([]),
            Self::WrongInitExecutable => {
                configuration["initProcess"]["executable"] = json!("/bin/sh")
            }
            Self::InitIsTheLockedIdentity => {
                configuration["initProcess"]["user"]["id"] = json!({"uid": 1000, "gid": 1000})
            }
            Self::RuntimeInitInterposed => configuration["useInit"] = json!(true),
        }
    }
}

/// Every single-field departure from the launch is refused. The sweep is the
/// oracle: a readback that checked four of the five fields would pass every
/// test that only exercised the four.
#[test]
fn every_departure_from_the_launch_is_refused() {
    for departure in Departure::ALL {
        let verdict = shape(|configuration| departure.apply(configuration)).verify(&admitted());
        assert!(
            verdict.is_err(),
            "{departure:?} should be refused, got {verdict:?}"
        );
    }
}

/// A container running an image other than the admitted one is refused for
/// *that* reason, so an operator is not sent looking at capabilities.
#[test]
fn a_wrong_image_is_reported_as_a_wrong_image() {
    let verdict = shape(|configuration| Departure::WrongImage.apply(configuration))
        .verify(&admitted())
        .unwrap_err();
    assert!(matches!(verdict, LockedShapeMismatch::ImageDigest { .. }));
}

/// Capabilities spelled the way `--cap-add` spells them are a set this host
/// does not recognise, not a match. This is the readback earning its keep:
/// comparing the strings the launch sent would have accepted it.
#[test]
fn argv_spelled_capabilities_do_not_satisfy_the_readback() {
    let verdict = shape(|configuration| Departure::ArgvSpelledCapabilities.apply(configuration))
        .verify(&admitted())
        .unwrap_err();
    assert!(matches!(verdict, LockedShapeMismatch::Capabilities { .. }));
}

proptest! {
    /// Any digest other than the admitted one is refused, whatever it is.
    #[test]
    fn only_the_admitted_digest_verifies(hex in "[0-9a-f]{64}") {
        let digest = format!("sha256:{hex}");
        let running = shape(|configuration| {
            configuration["image"]["descriptor"]["digest"] = json!(digest);
        });
        let verdict = running.verify(&admitted());
        prop_assert_eq!(verdict.is_ok(), digest == ADMITTED_DIGEST);
    }
}

/// Output that is not one container's document is refused rather than guessed
/// at: `container inspect` given a name that matches nothing prints an empty
/// list, which is not a container to verify.
#[test]
fn output_that_is_not_one_container_is_refused() {
    assert_eq!(
        LockedContainerShape::parse("[]"),
        Err(LockedShapeParseError::NotExactlyOneContainer(0))
    );
    assert_eq!(
        LockedContainerShape::parse("not json"),
        Err(LockedShapeParseError::Malformed)
    );
}

/// The runtime's own init process makes every other claim about "PID 1" a
/// claim about the wrong process: the configured executable becomes its
/// child, and the release gate's later read of `/proc/1/status` would be
/// reading the runtime's init rather than the initializer.
#[test]
fn an_interposed_runtime_init_is_refused() {
    let verdict = shape(|configuration| Departure::RuntimeInitInterposed.apply(configuration))
        .verify(&admitted())
        .unwrap_err();
    assert_eq!(verdict, LockedShapeMismatch::RuntimeInitInterposed);
}
