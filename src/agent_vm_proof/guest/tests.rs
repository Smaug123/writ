//! Tests for the guest report.
//!
//! The oracle is Stage E3b's. Every guest-reported fact the harness reads is a
//! slot whose capture is a claim; the verdict is the host's or withdrawn,
//! whatever the guest said; and a fabricated report can do no better than
//! leave the host's verdict alone.

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;

/// What each slot's guest command prints on a run that passes, in the shapes
/// measured on Apple `container` 1.4.1 with `alpine:latest` (busybox): `ip -6`
/// exits 0 and prints nothing under `ipv6.disable=1`, and a blocked `wget`
/// exits 1.
fn honest(slot: GuestSlot) -> &'static str {
    match slot {
        GuestSlot::ReleaseMarker => "released\n",
        GuestSlot::Pid1Cmdline => {
            "sh -c printf lifecycle-released >/tmp/writ-agent-vm-released; while :; do sleep 600; done \n"
        }
        GuestSlot::Pid1Status => HONEST_STATUS,
        GuestSlot::ProbeTools => "ip\nwget\nnslookup\n",
        GuestSlot::Ipv6AtStart | GuestSlot::Ipv6AfterReenable => {
            "sysctl absent\naddr-exit 0\nroute-exit 0\n"
        }
        GuestSlot::BrokerFetch => "exit 0\nbroker-ok\n",
        GuestSlot::ForbiddenFetch => {
            "exit 1\nwget: can't connect to remote host: Connection refused\n"
        }
        GuestSlot::InternetFetch => {
            "exit 1\nwget: can't connect to remote host: Connection refused\n"
        }
        GuestSlot::DnsLookup => "exit 1\n",
    }
}

/// Apple `container`'s default capability set (`00000000a80425fb`) with
/// `NET_RAW` dropped, as the IPv4-only launch passes `--cap-drop NET_RAW`.
const HONEST_STATUS: &str = "Name:\tsh\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t1\n\
CapInh:\t0000000000000000\nCapPrm:\t00000000a80405fb\nCapEff:\t00000000a80405fb\n\
CapBnd:\t00000000a80405fb\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";

fn capture(text: &str) -> Claim<RawCapture> {
    Claim::asserted(RawCapture::capture(text, GUEST_CAPTURE_LIMIT))
}

fn honest_report() -> GuestReport {
    GuestReport::new(|slot| capture(honest(slot)))
}

fn report_with(slot: GuestSlot, text: &str) -> GuestReport {
    GuestReport::new(|each| capture(if each == slot { text } else { honest(each) }))
}

/// The positive control for everything below: a run that passes raises no
/// doubt, so the grading is not vacuously inconclusive.
#[test]
fn an_honest_report_leaves_a_proven_verdict_proven() {
    assert_eq!(
        grade_guest_report(SessionVerdict::Proven, &honest_report()),
        GuestGrading {
            verdict: SessionVerdict::Proven,
            doubted_by: Vec::new(),
        }
    );
}

/// Every slot is read. A slot whose parser was dropped, or read the wrong
/// capture, would leave this one's garbage unnoticed.
#[test]
fn a_garbled_answer_to_any_one_question_withdraws_the_verdict_and_names_it() {
    for slot in GuestSlot::ALL {
        for garbage in ["", "\n", "garbage\n", "exit 0\n"] {
            // `exit 0` is a well-formed and passing answer only for the
            // broker fetch's status line, and the broker needs its body too.
            let graded = grade_guest_report(SessionVerdict::Proven, &report_with(slot, garbage));
            assert_eq!(
                graded,
                GuestGrading {
                    verdict: SessionVerdict::Inconclusive,
                    doubted_by: vec![slot],
                },
                "{slot:?} given {garbage:?}"
            );
        }
    }
}

/// What a compromised guest *saying* the bad thing looks like, per slot: each
/// is a report a passing run never makes.
#[test]
fn a_guest_reporting_the_failure_withdraws_the_verdict() {
    let bad: [(GuestSlot, &str); 11] = [
        (GuestSlot::ReleaseMarker, "absent\n"),
        (GuestSlot::Pid1Cmdline, "/sbin/writ-prelaunch-gate \n"),
        (
            GuestSlot::Pid1Status,
            &HONEST_STATUS.replace("CapBnd:\t00000000a80405fb", "CapBnd:\t00000000a80425fb"),
        ),
        (GuestSlot::ProbeTools, "ip\nwget\n"),
        (
            GuestSlot::Ipv6AtStart,
            "sysctl present\naddr-exit 0\naddr 2: eth0    inet6 fd83::2/64 scope global\nroute-exit 0\n",
        ),
        (
            GuestSlot::Ipv6AtStart,
            "sysctl present\naddr-exit 0\nroute-exit 0\nroute default via fe80::1 dev eth0\n",
        ),
        (GuestSlot::BrokerFetch, "exit 1\nwget: download timed out\n"),
        (GuestSlot::ForbiddenFetch, "exit 0\nforbidden-open\n"),
        (GuestSlot::InternetFetch, "exit 0\n<html></html>\n"),
        (GuestSlot::DnsLookup, "exit 0\n"),
        (
            GuestSlot::Ipv6AfterReenable,
            "sysctl present\naddr-exit 0\nroute-exit 0\n",
        ),
    ];
    for (slot, text) in bad {
        assert_eq!(
            grade_guest_report(SessionVerdict::Proven, &report_with(slot, text)).verdict,
            SessionVerdict::Inconclusive,
            "{slot:?} given {text:?}"
        );
    }
}

/// The at-start read asks about routability alone: which way the sysctl tree
/// is depends on the profile. The after-reenable read also asks that the tree
/// is gone, because this harness's profile disables IPv6 on the kernel line.
#[test]
fn only_the_after_reenable_read_requires_the_sysctl_tree_gone() {
    let tree_present = "sysctl present\naddr-exit 0\nroute-exit 0\n";
    assert!(reports_no_routable_ipv6(tree_present));
    assert!(!reports_no_ipv6_stack(tree_present));
}

#[test]
fn the_ipv6_posture_grammar_is_exact() {
    assert_eq!(
        parse_ipv6_posture("sysctl absent\naddr-exit 0\naddr a\naddr b\nroute-exit 2\nroute c\n"),
        Some(Ipv6Posture {
            sysctl_present: false,
            addr_exit: "0".to_string(),
            addrs: 2,
            route_exit: "2".to_string(),
            routes: 1,
        })
    );
    for malformed in [
        "addr-exit 0\nroute-exit 0\n",
        "sysctl absent\nroute-exit 0\naddr-exit 0\n",
        "sysctl absent\naddr-exit 0\nroute-exit 0\nextra\n",
        "sysctl absent\naddr-exit 0\nnoise\nroute-exit 0\n",
        "sysctl maybe\naddr-exit 0\nroute-exit 0\n",
    ] {
        assert_eq!(parse_ipv6_posture(malformed), None, "{malformed:?}");
    }
    // A failed read is not an empty one.
    assert!(!reports_no_routable_ipv6(
        "sysctl absent\naddr-exit 1\nroute-exit 0\n"
    ));
}

#[test]
fn a_probe_status_line_is_exact() {
    assert_eq!(parse_exit("exit 0\nbody\n"), Some((0, "body\n")));
    assert_eq!(parse_exit("exit 7"), Some((7, "")));
    for malformed in [
        "",
        "exit\n",
        "exit \n",
        "exit -1\n",
        "exit 1x\n",
        " exit 1\n",
        "Exit 1\n",
    ] {
        assert_eq!(parse_exit(malformed), None, "{malformed:?}");
    }
    // The broker's body must be exactly the broker's.
    assert!(!fetched_broker("exit 0\nbroker-ok\nmore\n"));
    assert!(!fetched_broker("exit 0\n"));
}

// ---------------------------------------------------------------------------
// The capability decoder, against a reference model.
// ---------------------------------------------------------------------------

fn render_status(sets: &[(&str, u64)], noise: &[String]) -> String {
    let mut text = String::new();
    for line in noise {
        text.push_str(line);
        text.push('\n');
    }
    for (name, mask) in sets {
        text.push_str(&format!("{name}:\t{mask:016x}\n"));
    }
    text
}

fn noise_line() -> impl Strategy<Value = String> {
    // Status lines that are not capability sets, including near misses.
    prop_oneof![
        "[A-Za-z]{1,12}:\t[a-z0-9 ()]{0,20}".prop_filter("not a capability set", |line| {
            !CAPABILITY_SETS
                .iter()
                .any(|set| line.starts_with(&format!("{set}:")))
        }),
        Just("CapInhX:\tffffffffffffffff".to_string()),
        Just("Cap:\tffffffffffffffff".to_string()),
    ]
}

proptest! {
    /// The parser holds no authority exactly when the model says so: all
    /// five sets present once, and none carrying bit 12 or bit 13.
    #[test]
    fn the_capability_decoder_agrees_with_the_model(
        masks in proptest::array::uniform5(any::<u64>()),
        order in Just(CAPABILITY_SETS).prop_shuffle(),
        noise in proptest::collection::vec(noise_line(), 0..4),
    ) {
        let sets: Vec<(&str, u64)> = order
            .iter()
            .map(|name| {
                let index = CAPABILITY_SETS.iter().position(|set| set == name).unwrap();
                (*name, masks[index])
            })
            .collect();
        let expected = masks
            .iter()
            .all(|mask| mask & (1 << CAP_NET_ADMIN) == 0 && mask & (1 << CAP_NET_RAW) == 0);
        prop_assert_eq!(holds_no_network_authority(&render_status(&sets, &noise)), expected);
    }

    /// A set that is missing, or appears twice, is doubt — even when every
    /// mask that is there is clean. A decoder that read only the sets it
    /// found would pass a guest that hid the one holding `NET_RAW`.
    #[test]
    fn a_missing_or_repeated_set_is_doubt(
        drop in 0_usize..5,
        repeat in any::<bool>(),
    ) {
        let mut sets: Vec<(&str, u64)> = CAPABILITY_SETS.iter().map(|name| (*name, 0)).collect();
        if repeat {
            sets.push(sets[drop]);
        } else {
            sets.remove(drop);
        }
        prop_assert!(!holds_no_network_authority(&render_status(&sets, &[])));
    }
}

#[test]
fn the_default_set_holds_net_raw_and_a_malformed_mask_is_doubt() {
    // Apple `container`'s documented default holds NET_RAW and not NET_ADMIN.
    let default = HONEST_STATUS.replace("00000000a80405fb", "00000000a80425fb");
    assert!(!holds_no_network_authority(&default));
    assert!(holds_no_network_authority(HONEST_STATUS));
    for mask in ["", "00000000000000000", "zz", "-1", "0x00"] {
        let status =
            HONEST_STATUS.replace("CapAmb:\t0000000000000000", &format!("CapAmb:\t{mask}"));
        assert!(!holds_no_network_authority(&status), "{mask:?}");
    }
}

// ---------------------------------------------------------------------------
// Whatever the guest says, the verdict is the host's or withdrawn.
// ---------------------------------------------------------------------------

fn host_verdict() -> impl Strategy<Value = SessionVerdict> {
    prop_oneof![
        Just(SessionVerdict::Proven),
        Just(SessionVerdict::Inconclusive)
    ]
}

/// A capture per slot: anything at all, or a well-formed answer, or the
/// passing one — so the generated reports reach every parser's accepting
/// branch as well as its refusals.
fn arbitrary_report() -> impl Strategy<Value = GuestReport> {
    let one = |slot: GuestSlot| {
        prop_oneof![
            ".{0,40}",
            "(exit [0-9]\n)?[a-z -]{0,12}\n?",
            Just(honest(slot).to_string()),
        ]
    };
    GuestSlot::ALL
        .map(one)
        .prop_map(|texts| GuestReport::new(|slot| capture(&texts[slot as usize])))
}

proptest! {
    /// Evidence protocol rule 2: a claim can lower confidence and never raise
    /// it. Whatever the report, the verdict is either the one the host
    /// brought or withdrawn — and nothing rescues a host that brought none.
    #[test]
    fn the_verdict_is_the_hosts_or_withdrawn(host in host_verdict(), report in arbitrary_report()) {
        let verdict = grade_guest_report(host, &report).verdict;
        prop_assert!(verdict == host || verdict == SessionVerdict::Inconclusive);
        if host == SessionVerdict::Inconclusive {
            prop_assert_eq!(verdict, SessionVerdict::Inconclusive);
        }
    }

    /// The plan's "grading twice": once over the real report and once over a
    /// fabricated one. The best a fabricator can do is the passing answer to
    /// every question, and that yields exactly the host's verdict — so no
    /// fabricated report moves the verdict anywhere the real one could not,
    /// and the two agree wherever neither was withdrawn.
    #[test]
    fn a_fabricated_report_does_no_better_than_the_hosts_own_verdict(
        host in host_verdict(),
        real in arbitrary_report(),
        fabricated in arbitrary_report(),
    ) {
        prop_assert_eq!(grade_guest_report(host, &honest_report()).verdict, host);
        let from_real = grade_guest_report(host, &real).verdict;
        let from_fabricated = grade_guest_report(host, &fabricated).verdict;
        if from_real != SessionVerdict::Inconclusive && from_fabricated != SessionVerdict::Inconclusive {
            prop_assert_eq!(from_real, from_fabricated);
        }
    }

    /// The diagnostics name exactly the slots that withdraw the verdict.
    #[test]
    fn the_verdict_is_withdrawn_exactly_when_some_slot_is_named(report in arbitrary_report()) {
        let graded = grade_guest_report(SessionVerdict::Proven, &report);
        prop_assert_eq!(
            graded.verdict == SessionVerdict::Inconclusive,
            !graded.doubted_by.is_empty()
        );
    }
}

// ---------------------------------------------------------------------------
// The report and the script it is read from.
// ---------------------------------------------------------------------------

#[test]
fn read_dir_refuses_a_missing_or_unknown_capture_and_bounds_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    for slot in GuestSlot::ALL {
        std::fs::write(
            dir.path().join(format!("{}.txt", slot.name())),
            honest(slot),
        )
        .unwrap();
    }
    let report = GuestReport::read_dir(dir.path()).unwrap();
    assert_eq!(
        grade_guest_report(SessionVerdict::Proven, &report).verdict,
        SessionVerdict::Proven
    );

    // A capture larger than the bound is truncated, not read whole.
    let huge = format!("released\n{}", "x".repeat(GUEST_CAPTURE_LIMIT * 2));
    std::fs::write(dir.path().join("release-marker.txt"), &huge).unwrap();
    let report = GuestReport::read_dir(dir.path()).unwrap();
    assert_eq!(
        report.claim(GuestSlot::ReleaseMarker).captured_bytes(),
        GUEST_CAPTURE_LIMIT
    );
    assert_eq!(
        grade_guest_report(SessionVerdict::Proven, &report).doubted_by,
        vec![GuestSlot::ReleaseMarker]
    );

    std::fs::write(dir.path().join("mystery.txt"), "").unwrap();
    assert!(matches!(
        GuestReport::read_dir(dir.path()),
        Err(GuestReportError::Unknown(name)) if name == "mystery.txt"
    ));
    std::fs::remove_file(dir.path().join("mystery.txt")).unwrap();

    std::fs::remove_file(dir.path().join("dns-lookup.txt")).unwrap();
    assert!(matches!(
        GuestReport::read_dir(dir.path()),
        Err(GuestReportError::Missing("dns-lookup"))
    ));
}

const HARNESS: &str = include_str!("../../../scripts/prove-agent-vm-lifecycle.sh");

/// The functions of the harness that may run a command in the guest. Two
/// capture or command, and never let the shell branch on what came back; the
/// third is the failure dump, which runs after the verdict is already a
/// failure.
const GUEST_EXEC_FUNCTIONS: [&str; 3] = ["guest_report", "guest_act", "dump_pf_diagnostics"];

/// Every guest-reported fact the harness reads is a slot, and every slot is a
/// claim. The script is the list of what the harness reads: each
/// `guest_report <slot>` is one question, asked once, and naming one the
/// grader has no parser for fails here rather than on hardware.
#[test]
fn every_question_the_harness_asks_the_guest_is_a_claim_slot() {
    let asked: Vec<&str> = HARNESS
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("guest_report "))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    let asked_set: BTreeSet<&str> = asked.iter().copied().collect();
    assert_eq!(
        asked.len(),
        asked_set.len(),
        "a question asked twice: {asked:?}"
    );
    let slots: BTreeSet<&str> = GuestSlot::ALL.iter().map(|slot| slot.name()).collect();
    assert_eq!(asked_set, slots);

    // And the type the grader holds each answer as. This is what a new
    // question has to be: there is no other shape for it to take.
    let report = honest_report();
    for slot in GuestSlot::ALL {
        let _claim: &Claim<RawCapture> = report.claim(slot);
    }
}

/// Nothing else in the harness runs a command in the guest, so nothing else
/// can read an answer the grader does not see.
#[test]
fn only_the_capture_and_command_helpers_exec_into_the_guest() {
    let mut function = None;
    let mut executing = BTreeSet::new();
    for line in HARNESS.lines() {
        if let Some(name) = line.strip_suffix("() {") {
            function = Some(name.to_string());
        } else if line == "}" {
            function = None;
        }
        if line.contains("container exec") {
            executing.insert(
                function
                    .clone()
                    .unwrap_or_else(|| "<top level>".to_string()),
            );
        }
    }
    let allowed: BTreeSet<String> = GUEST_EXEC_FUNCTIONS
        .iter()
        .map(|name| name.to_string())
        .collect();
    assert_eq!(executing, allowed);
}

/// The harness truncates each answer at the bound the grader reads to, so
/// neither can see more of an answer than the other.
#[test]
fn the_harness_and_the_grader_bound_answers_alike() {
    let bound = format!("GUEST_CAPTURE_LIMIT={GUEST_CAPTURE_LIMIT}");
    assert_eq!(
        HARNESS.lines().filter(|line| *line == bound).count(),
        1,
        "{bound}"
    );
}

/// An answer that reaches the bound is one whose end the host never saw, and
/// what it did not see could contradict what it did: five clean capability
/// sets, padding, then a set holding `NET_RAW` past the cut. Reaching the
/// bound is doubt in itself, whatever the prefix parses to.
#[test]
fn an_answer_that_reaches_the_bound_is_doubt_whatever_its_prefix_says() {
    let mut status = HONEST_STATUS.to_string();
    while status.len() < GUEST_CAPTURE_LIMIT {
        status.push_str("Padding:\t0\n");
    }
    status.push_str("CapBnd:\t00000000a80425fb\n");
    // The retained prefix alone parses clean: the contradiction is past the cut.
    assert!(holds_no_network_authority(&status[..GUEST_CAPTURE_LIMIT]));

    // Through the constructor the tests use.
    let graded = grade_guest_report(
        SessionVerdict::Proven,
        &report_with(GuestSlot::Pid1Status, &status),
    );
    assert_eq!(graded.doubted_by, vec![GuestSlot::Pid1Status]);

    // And through the directory the harness writes, where `head -c` has
    // already cut the answer at exactly the bound.
    let dir = tempfile::tempdir().unwrap();
    for slot in GuestSlot::ALL {
        std::fs::write(
            dir.path().join(format!("{}.txt", slot.name())),
            honest(slot),
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join("pid1-status.txt"),
        &status.as_bytes()[..GUEST_CAPTURE_LIMIT],
    )
    .unwrap();
    let graded = grade_guest_report(
        SessionVerdict::Proven,
        &GuestReport::read_dir(dir.path()).unwrap(),
    );
    assert_eq!(graded.doubted_by, vec![GuestSlot::Pid1Status]);

    // One byte short of the bound is an answer the host saw whole.
    let whole = format!(
        "{HONEST_STATUS}{}",
        "x".repeat(GUEST_CAPTURE_LIMIT - 1 - HONEST_STATUS.len())
    );
    assert_eq!(
        grade_guest_report(
            SessionVerdict::Proven,
            &report_with(GuestSlot::Pid1Status, &whole)
        )
        .verdict,
        SessionVerdict::Proven
    );
}

/// An answer that is not UTF-8 is not one the host read whole. Lossy decoding
/// turns each bad byte into a three-byte replacement character, so an answer
/// well under the bound on disk can overrun it once decoded, and the cut then
/// drops a tail the byte count never saw: here, the set holding `NET_RAW`.
#[test]
fn an_answer_that_is_not_utf8_is_doubt_even_under_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    for slot in GuestSlot::ALL {
        std::fs::write(
            dir.path().join(format!("{}.txt", slot.name())),
            honest(slot),
        )
        .unwrap();
    }
    let mut status = HONEST_STATUS.as_bytes().to_vec();
    status.extend(std::iter::repeat_n(0xff_u8, 23_000));
    status.extend_from_slice(b"\nCapBnd:\t00000000a80425fb\n");
    assert!(status.len() < GUEST_CAPTURE_LIMIT);
    std::fs::write(dir.path().join("pid1-status.txt"), &status).unwrap();
    let graded = grade_guest_report(
        SessionVerdict::Proven,
        &GuestReport::read_dir(dir.path()).unwrap(),
    );
    assert_eq!(graded.doubted_by, vec![GuestSlot::Pid1Status]);

    // One bad byte in an otherwise passing answer is doubt too.
    std::fs::write(
        dir.path().join("pid1-status.txt"),
        honest(GuestSlot::Pid1Status),
    )
    .unwrap();
    std::fs::write(dir.path().join("release-marker.txt"), b"released\xff\n").unwrap();
    let graded = grade_guest_report(
        SessionVerdict::Proven,
        &GuestReport::read_dir(dir.path()).unwrap(),
    );
    assert_eq!(graded.doubted_by, vec![GuestSlot::ReleaseMarker]);
}
