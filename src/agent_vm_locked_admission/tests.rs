//! Tests for the locked profile's admission evidence.
//!
//! Three oracles, from Stage D of
//! `docs/plans/2026-09-01-ipv4-only-locked-v1.md`:
//!
//! 1. `admit_locked` is swept exhaustively over the grid of facts — every
//!    combination of helper version, preflight verdict, image ABI label,
//!    image digest, CLI version and macOS build — and only the one admitting
//!    combination yields `Ok`, with every refusal naming a fact that really
//!    is wrong in that cell.
//! 2. The gatherer, against a fake tool: a probe that hangs, floods its cap,
//!    exits non-zero, or prints something unreadable yields the corresponding
//!    unreadable fact, never a panic and never an admission.
//! 3. The shipped allowlist admits nothing, because it is empty until the
//!    vertical proof has been run.

use std::fs;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::*;
use crate::agent_vm_firewall::{PassTranslationRule, PfPreflightReport, SessionAnchorPlacement};
use crate::agent_vm_pf_helper_policy::{PfHelperPolicy, parse_ipv4_cidr, parse_ipv6_cidr};
use crate::core::{AgentNetworkPool, BrokerPortRange};
use crate::test_support::write_executable_script;

/// A real `container image inspect` document, captured from Apple
/// `container` 1.4.1 against the official guest image. The fixture is the
/// tool's own output rather than a hand-written approximation of it, so a
/// parser that only works on what we imagined the tool prints fails here.
const REAL_INSPECT: &str = include_str!("container-image-inspect.json");

const REAL_CLI_LINE: &str = "container CLI version 1.4.1 (build: release, commit: 9a8917c)";
const REAL_BUILD: &str = "25G72";
const REAL_DIGEST: &str = "sha256:43e3ddf5916cc8580ccdda597a4cf9bf067a91fbfac0f1043943a68366cd32b9";

/// A platform triple that no proof run will ever record: the commit is all
/// zeroes and the digest is all zeroes. The sweep below pins against this
/// rather than against a real platform, so the "the shipped allowlist admits
/// nothing" assertion stays true once Stage E3 adds a real record.
const SYNTHETIC_CLI_LINE: &str = "container CLI version 0.0.0 (build: synthetic, commit: 0000000)";
const SYNTHETIC_BUILD: &str = "0Z0";
const SYNTHETIC_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Another triple, every component different from the synthetic one.
const OTHER_CLI_LINE: &str = "container CLI version 0.0.1 (build: synthetic, commit: 1111111)";
const OTHER_BUILD: &str = "0Z1";
const OTHER_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn test_policy() -> PfHelperPolicy {
    PfHelperPolicy::new(
        AgentNetworkPool::new(
            parse_ipv4_cidr("10.200.0.0/16").unwrap(),
            parse_ipv6_cidr("fd00:7772:6974::/48").unwrap(),
        )
        .unwrap(),
        BrokerPortRange::new(49152, 65535).unwrap(),
    )
}

fn preflight_doc(report: PfPreflightReport) -> PfHelperPreflightDoc {
    PfHelperPreflightDoc::new(report, test_policy())
}

fn clean_report() -> PfPreflightReport {
    PfPreflightReport {
        pf_enabled: true,
        session_anchor: SessionAnchorPlacement::First,
        pass_translation_rules: Vec::new(),
    }
}

fn anchor_absent_report() -> PfPreflightReport {
    PfPreflightReport {
        session_anchor: SessionAnchorPlacement::Absent,
        ..clean_report()
    }
}

fn quick_pass_ahead_report() -> PfPreflightReport {
    PfPreflightReport {
        session_anchor: SessionAnchorPlacement::Preceded(vec![
            "pass in quick on en0 all".to_string(),
        ]),
        ..clean_report()
    }
}

fn pass_translation_report() -> PfPreflightReport {
    PfPreflightReport {
        pass_translation_rules: vec![PassTranslationRule {
            anchor: Some("com.apple/x".to_string()),
            rule: "nat pass on en0 from any to any -> (en0)".to_string(),
        }],
        ..clean_report()
    }
}

// --- the exhaustive sweep ---------------------------------------------------

/// One cell of the grid: the value each fact takes, and whether it is the
/// admitting one.
#[derive(Clone, Debug)]
struct Cell<T> {
    name: &'static str,
    observed: Observed<T>,
    admitting: bool,
}

fn helper_cells() -> Vec<Cell<PfHelperProtocolDoc>> {
    vec![
        Cell {
            name: "helper v2",
            observed: Observed::Read(PfHelperProtocolDoc::with_version(
                PF_HELPER_PROTOCOL_VERSION,
            )),
            admitting: true,
        },
        Cell {
            name: "helper v1",
            observed: Observed::Read(PfHelperProtocolDoc::with_version(1)),
            admitting: false,
        },
        Cell {
            name: "helper unreadable",
            observed: Observed::Unreadable(ProbeFailure::Unparseable),
            admitting: false,
        },
    ]
}

fn preflight_cells() -> Vec<Cell<PfHelperPreflightDoc>> {
    vec![
        Cell {
            name: "preflight clean",
            observed: Observed::Read(preflight_doc(clean_report())),
            admitting: true,
        },
        Cell {
            name: "preflight anchor absent",
            observed: Observed::Read(preflight_doc(anchor_absent_report())),
            admitting: false,
        },
        Cell {
            name: "preflight quick pass ahead",
            observed: Observed::Read(preflight_doc(quick_pass_ahead_report())),
            admitting: false,
        },
        Cell {
            name: "preflight pass translation rule",
            observed: Observed::Read(preflight_doc(pass_translation_report())),
            admitting: false,
        },
        Cell {
            name: "preflight unreadable",
            observed: Observed::Unreadable(ProbeFailure::Failed),
            admitting: false,
        },
    ]
}

fn abi_cells() -> Vec<Cell<ImageIsolationAbi>> {
    vec![
        Cell {
            name: "abi 1",
            observed: Observed::Read(ImageIsolationAbi::Version(ISOLATION_ABI_VERSION)),
            admitting: true,
        },
        Cell {
            name: "abi 0",
            observed: Observed::Read(ImageIsolationAbi::Version(0)),
            admitting: false,
        },
        Cell {
            name: "abi absent",
            observed: Observed::Read(ImageIsolationAbi::Absent),
            admitting: false,
        },
        Cell {
            name: "abi unreadable",
            observed: Observed::Unreadable(ProbeFailure::Unparseable),
            admitting: false,
        },
    ]
}

fn digest_cells() -> Vec<Cell<ImageDigest>> {
    vec![
        Cell {
            name: "digest listed",
            observed: Observed::Read(ImageDigest::parse(SYNTHETIC_DIGEST).unwrap()),
            admitting: true,
        },
        Cell {
            name: "digest other",
            observed: Observed::Read(ImageDigest::parse(OTHER_DIGEST).unwrap()),
            admitting: false,
        },
        Cell {
            name: "digest unreadable",
            observed: Observed::Unreadable(ProbeFailure::Unparseable),
            admitting: false,
        },
    ]
}

fn cli_cells() -> Vec<Cell<ContainerCliVersion>> {
    vec![
        Cell {
            name: "cli listed",
            observed: Observed::Read(ContainerCliVersion::parse(SYNTHETIC_CLI_LINE).unwrap()),
            admitting: true,
        },
        Cell {
            name: "cli other",
            observed: Observed::Read(ContainerCliVersion::parse(OTHER_CLI_LINE).unwrap()),
            admitting: false,
        },
        Cell {
            name: "cli unreadable",
            observed: Observed::Unreadable(ProbeFailure::Spawn),
            admitting: false,
        },
    ]
}

fn build_cells() -> Vec<Cell<MacOsBuild>> {
    vec![
        Cell {
            name: "build listed",
            observed: Observed::Read(MacOsBuild::parse(SYNTHETIC_BUILD).unwrap()),
            admitting: true,
        },
        Cell {
            name: "build other",
            observed: Observed::Read(MacOsBuild::parse(OTHER_BUILD).unwrap()),
            admitting: false,
        },
        Cell {
            name: "build unreadable",
            observed: Observed::Unreadable(ProbeFailure::TimedOut),
            admitting: false,
        },
    ]
}

fn synthetic_allowlist() -> ProvenPlatforms {
    ProvenPlatforms::new([ProvenPlatform::parse(
        SYNTHETIC_CLI_LINE,
        SYNTHETIC_BUILD,
        SYNTHETIC_DIGEST,
    )
    .unwrap()])
}

/// Walk the whole grid, applying `check` to each cell.
fn for_each_cell(mut check: impl FnMut(LockedV1RuntimeEvidence, [&'static str; 6], [bool; 6])) {
    for helper in helper_cells() {
        for preflight in preflight_cells() {
            for abi in abi_cells() {
                for digest in digest_cells() {
                    for cli in cli_cells() {
                        for build in build_cells() {
                            let evidence = LockedV1RuntimeEvidence {
                                helper_protocol: helper.observed.clone(),
                                preflight: preflight.observed.clone(),
                                image_isolation_abi: abi.observed.clone(),
                                image_digest: digest.observed.clone(),
                                container_cli: cli.observed.clone(),
                                macos_build: build.observed.clone(),
                            };
                            check(
                                evidence,
                                [
                                    helper.name,
                                    preflight.name,
                                    abi.name,
                                    digest.name,
                                    cli.name,
                                    build.name,
                                ],
                                [
                                    helper.admitting,
                                    preflight.admitting,
                                    abi.admitting,
                                    digest.admitting,
                                    cli.admitting,
                                    build.admitting,
                                ],
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Which fact each position of the grid is about, in the order
/// [`for_each_cell`] reports them.
const FACT_ORDER: [LockedV1Fact; 6] = [
    LockedV1Fact::HelperProtocol,
    LockedV1Fact::Preflight,
    LockedV1Fact::ImageIsolationAbi,
    LockedV1Fact::ImageDigest,
    LockedV1Fact::ContainerCli,
    LockedV1Fact::MacOsBuild,
];

/// Exactly one combination of the six facts admits, and every refusal names a
/// fact that is genuinely wrong in that cell.
///
/// The second half is the part with teeth: it is not enough to refuse, the
/// refusal has to send the operator to a probe that is actually failing.
#[test]
fn admit_locked_admits_exactly_one_combination_and_names_a_wrong_fact() {
    let allowlist = synthetic_allowlist();
    let mut admitted = 0usize;
    let mut cells = 0usize;
    for_each_cell(|evidence, names, admitting| {
        cells += 1;
        let verdict = ConfiguredIpv6Profile::Ipv4OnlyLockedV1.admit_locked(&evidence, &allowlist);
        let all_admitting = admitting.iter().all(|ok| *ok);
        match verdict {
            Ok(admission) => {
                assert!(
                    all_admitting,
                    "{names:?} admitted, but not every fact is the admitting one"
                );
                assert_eq!(
                    admission.image_digest().as_str(),
                    SYNTHETIC_DIGEST,
                    "the admission carries the proven record's digest"
                );
                admitted += 1;
            }
            Err(refused) => {
                assert!(
                    !all_admitting,
                    "{names:?} refused with {refused}, but every fact is the admitting one"
                );
                let named = refused.fact();
                let position = FACT_ORDER
                    .iter()
                    .position(|fact| *fact == named)
                    .unwrap_or_else(|| panic!("{names:?}: refusal named {named:?}"));
                assert!(
                    !admitting[position],
                    "{names:?}: refused naming {named:?} ({refused}), but that fact is fine"
                );
            }
        }
    });
    assert_eq!(
        cells,
        3 * 5 * 4 * 3 * 3 * 3,
        "the grid is the whole product"
    );
    assert_eq!(admitted, 1, "exactly one cell admits");
}

/// The shipped allowlist is empty, so nothing at all admits under it — which
/// is what "the profile stays closed at the end of this stage" means for the
/// half of the decision the allowlist owns.
#[test]
fn the_shipped_allowlist_admits_nothing() {
    let shipped = ProvenPlatforms::shipped();
    for_each_cell(|evidence, names, _| {
        let verdict = ConfiguredIpv6Profile::Ipv4OnlyLockedV1.admit_locked(&evidence, &shipped);
        assert!(
            verdict.is_err(),
            "{names:?} admitted under the shipped allowlist"
        );
    });
}

/// Every literal in the shipped allowlist parses. Vacuous while the list is
/// empty; it is here so that the first entry Stage E3 adds is checked by
/// `cargo test` rather than by a panic in the daemon.
#[test]
fn the_shipped_allowlist_parses() {
    let shipped = ProvenPlatforms::shipped();
    assert_eq!(
        shipped.records().len(),
        SHIPPED_PROVEN_PLATFORMS.len(),
        "every shipped literal parsed"
    );
}

/// `admit_locked` is about one profile. Under any other, it refuses without
/// looking at a single fact — the evidence here is perfect.
#[test]
fn another_profile_is_refused_whatever_the_evidence_says() {
    let allowlist = synthetic_allowlist();
    let evidence = admitting_evidence();
    for profile in [
        ConfiguredIpv6Profile::DualStackRequired,
        ConfiguredIpv6Profile::Ipv4OnlyNoGuestIpv6,
    ] {
        let refused = profile
            .admit_locked(&evidence, &allowlist)
            .expect_err("only ipv4_only_locked_v1 is decided here");
        assert_eq!(refused, LockedV1Refused::NotLockedProfile(profile));
        assert_eq!(refused.fact(), LockedV1Fact::ConfiguredProfile);
    }
    // And the admitting evidence really does admit under the right profile,
    // so the refusal above is about the profile and not about the facts.
    ConfiguredIpv6Profile::Ipv4OnlyLockedV1
        .admit_locked(&evidence, &allowlist)
        .expect("the evidence is the admitting combination");
}

/// `admit` is untouched: the profile is still closed on the spelling alone,
/// so nothing reaches a probe.
#[test]
fn admit_still_refuses_the_locked_profile() {
    assert_eq!(
        ConfiguredIpv6Profile::Ipv4OnlyLockedV1.admit(),
        Err(crate::agent_vm_lifecycle::Ipv6ProfileClosed::NotImplemented)
    );
}

fn admitting_evidence() -> LockedV1RuntimeEvidence {
    LockedV1RuntimeEvidence {
        helper_protocol: Observed::Read(PfHelperProtocolDoc::with_version(
            PF_HELPER_PROTOCOL_VERSION,
        )),
        preflight: Observed::Read(preflight_doc(clean_report())),
        image_isolation_abi: Observed::Read(ImageIsolationAbi::Version(ISOLATION_ABI_VERSION)),
        image_digest: Observed::Read(ImageDigest::parse(SYNTHETIC_DIGEST).unwrap()),
        container_cli: Observed::Read(ContainerCliVersion::parse(SYNTHETIC_CLI_LINE).unwrap()),
        macos_build: Observed::Read(MacOsBuild::parse(SYNTHETIC_BUILD).unwrap()),
    }
}

/// An allowlist is a trie, so a platform that leaves it part-way through is
/// told where: a proven CLI that was never proven with this macOS build is a
/// different sentence from an unproven CLI.
#[test]
fn a_partial_match_names_the_level_at_which_the_platform_left_the_allowlist() {
    let allowlist = ProvenPlatforms::new([
        ProvenPlatform::parse(SYNTHETIC_CLI_LINE, SYNTHETIC_BUILD, SYNTHETIC_DIGEST).unwrap(),
        ProvenPlatform::parse(SYNTHETIC_CLI_LINE, OTHER_BUILD, OTHER_DIGEST).unwrap(),
    ]);

    // Proven CLI, proven build, but that pair was never proven with this
    // image: the digest is named, not the CLI.
    let mut evidence = admitting_evidence();
    evidence.image_digest = Observed::Read(ImageDigest::parse(OTHER_DIGEST).unwrap());
    let refused = ConfiguredIpv6Profile::Ipv4OnlyLockedV1
        .admit_locked(&evidence, &allowlist)
        .expect_err("that pair was proven with the other image only");
    assert_eq!(refused.fact(), LockedV1Fact::ImageDigest);

    // The other record's (build, digest) pair, on the same CLI, admits.
    let mut evidence = admitting_evidence();
    evidence.macos_build = Observed::Read(MacOsBuild::parse(OTHER_BUILD).unwrap());
    evidence.image_digest = Observed::Read(ImageDigest::parse(OTHER_DIGEST).unwrap());
    ConfiguredIpv6Profile::Ipv4OnlyLockedV1
        .admit_locked(&evidence, &allowlist)
        .expect("the second record is proven");

    // An unproven CLI is named even though its build and digest are both
    // proven elsewhere in the list.
    let mut evidence = admitting_evidence();
    evidence.container_cli = Observed::Read(ContainerCliVersion::parse(OTHER_CLI_LINE).unwrap());
    let refused = ConfiguredIpv6Profile::Ipv4OnlyLockedV1
        .admit_locked(&evidence, &allowlist)
        .expect_err("that CLI is in no record");
    assert_eq!(refused.fact(), LockedV1Fact::ContainerCli);
}

// --- the parsers ------------------------------------------------------------

#[test]
fn the_real_container_version_line_parses_and_round_trips() {
    let parsed = ContainerCliVersion::parse(REAL_CLI_LINE).unwrap();
    assert_eq!(parsed.line(), REAL_CLI_LINE);
    assert_eq!(
        ContainerCliVersion::parse(&format!("{REAL_CLI_LINE}\n")).unwrap(),
        parsed,
        "the captured line may or may not carry its newline"
    );
}

#[test]
fn a_mangled_container_version_line_is_refused() {
    for bad in [
        "",
        "\n",
        "container CLI version 1.4.1",
        "container CLI version  (build: release, commit: 9a8917c)",
        "container CLI version 1.4.1 (build: , commit: 9a8917c)",
        "container CLI version 1.4.1 (build: release, commit: )",
        "container CLI version 1.4.1 (build: release, commit: 9A8917C)",
        "Container CLI version 1.4.1 (build: release, commit: 9a8917c)",
        "container CLI version 1.4.1 (build: release, commit: 9a8917c) extra",
        "container CLI version 1.4.1 (build: release, commit: 9a8917c)\n\n",
        "container CLI version 1.4.1 (build: release, commit: 9a8917c)\nand another",
    ] {
        assert!(
            ContainerCliVersion::parse(bad).is_err(),
            "accepted {bad:?} as a version line"
        );
    }
}

#[test]
fn real_macos_builds_parse_and_junk_does_not() {
    for good in ["25G72", "24A335", "23A5301h", "19H2026", "15A284"] {
        assert_eq!(MacOsBuild::parse(good).unwrap().as_str(), good);
        assert_eq!(
            MacOsBuild::parse(&format!("{good}\n")).unwrap().as_str(),
            good
        );
    }
    for bad in [
        "",
        "\n",
        "G72",
        "25",
        "25G",
        "25g72",
        "25G72 ",
        " 25G72",
        "25G72\n25G72",
        "25G72X",
        "macOS 26.6",
        "2222222222G22222222",
    ] {
        assert!(
            MacOsBuild::parse(bad).is_err(),
            "accepted {bad:?} as a build"
        );
    }
}

#[test]
fn image_digests_are_lowercase_sha256_and_nothing_else() {
    assert_eq!(
        ImageDigest::parse(REAL_DIGEST).unwrap().as_str(),
        REAL_DIGEST
    );
    let hex = &REAL_DIGEST[7..];
    for bad in [
        String::new(),
        hex.to_string(),
        format!("sha512:{hex}"),
        format!("sha256:{}", hex.to_uppercase()),
        format!("sha256:{}", &hex[1..]),
        format!("sha256:{hex}0"),
        format!("sha256:{hex}\n"),
    ] {
        assert!(
            ImageDigest::parse(&bad).is_err(),
            "accepted {bad:?} as a digest"
        );
    }
}

/// Every macOS build identifier the grammar admits: darwin major, one
/// capital, build number, optional seed suffix.
fn arb_macos_build() -> impl Strategy<Value = String> {
    "[0-9]{1,3}[A-Z][0-9]{1,5}[a-z]?"
}

fn arb_image_digest() -> impl Strategy<Value = String> {
    "sha256:[0-9a-f]{64}"
}

/// A version line built from its three components, rather than hoped for out
/// of arbitrary text: the shortest line this parser accepts is 45 characters,
/// so a character generator would never produce one.
fn arb_container_cli_line() -> impl Strategy<Value = String> {
    (
        "[0-9A-Za-z.+-]{1,12}",
        "[0-9A-Za-z-]{1,12}",
        "[0-9a-z]{1,12}",
    )
        .prop_map(|(version, build, commit)| {
            format!("container CLI version {version} (build: {build}, commit: {commit})")
        })
}

/// Splice one printable character into a string, or delete one: the near
/// misses that decide whether a parser is pinning a format or merely
/// recognising a prefix of one.
fn arb_one_edit(valid: String) -> impl Strategy<Value = String> {
    let len = valid.len();
    (0..=len, prop::option::of("[ -~]")).prop_map(move |(at, inserted)| {
        let mut edited = valid.clone();
        match inserted {
            Some(character) => edited.insert_str(at, &character),
            None if at < len => {
                edited.remove(at);
            }
            None => {}
        }
        edited
    })
}

proptest! {
    /// Every value these formats can take is accepted, and the parsed value
    /// reproduces it byte for byte. The second half is what an allowlist
    /// comparison rests on: a parser that dropped or normalised a component
    /// would equate two platforms that are not the same platform.
    ///
    /// The two line-oriented facts are read from a tool's stdout, which may or
    /// may not carry a trailing newline, so both spellings must parse to the
    /// same value. The digest is not: it is a JSON field, where a newline is
    /// not whitespace the format allows but a different string.
    #[test]
    fn every_valid_fact_parses_and_keeps_every_byte(
        build in arb_macos_build(),
        digest in arb_image_digest(),
        line in arb_container_cli_line(),
    ) {
        let parsed_build = MacOsBuild::parse(&build).unwrap();
        prop_assert_eq!(parsed_build.as_str(), build.as_str());
        let build_line = format!("{build}\n");
        let parsed_build_line = MacOsBuild::parse(&build_line).unwrap();
        prop_assert_eq!(parsed_build_line.as_str(), build.as_str());

        let parsed_digest = ImageDigest::parse(&digest).unwrap();
        prop_assert_eq!(parsed_digest.as_str(), digest.as_str());
        let digest_line = format!("{digest}\n");
        prop_assert!(ImageDigest::parse(&digest_line).is_err());

        prop_assert_eq!(ContainerCliVersion::parse(&line).unwrap().line(), line.clone());
        let cli_line = format!("{line}\n");
        prop_assert_eq!(ContainerCliVersion::parse(&cli_line).unwrap().line(), line);
    }

    /// One edit to a valid value is either refused or reproduced verbatim —
    /// never quietly read as the value it was edited from. Edits are where a
    /// too-lenient parser shows: this is the generator that actually reaches
    /// the boundary of each format, which arbitrary text does not.
    #[test]
    fn one_edit_to_a_valid_fact_is_refused_or_kept_verbatim(
        build in arb_macos_build().prop_flat_map(arb_one_edit),
        digest in arb_image_digest().prop_flat_map(arb_one_edit),
        line in arb_container_cli_line().prop_flat_map(arb_one_edit),
    ) {
        if let Ok(parsed) = MacOsBuild::parse(&build) {
            prop_assert_eq!(parsed.as_str(), build.strip_suffix('\n').unwrap_or(&build));
        }
        if let Ok(parsed) = ImageDigest::parse(&digest) {
            prop_assert_eq!(parsed.as_str(), digest.as_str());
        }
        if let Ok(parsed) = ContainerCliVersion::parse(&line) {
            prop_assert_eq!(parsed.line(), line.strip_suffix('\n').unwrap_or(&line));
        }
    }

    /// No input, however hostile, panics a parser.
    #[test]
    fn parsers_never_panic(text in ".{0,200}") {
        let _ = MacOsBuild::parse(&text);
        let _ = ImageDigest::parse(&text);
        let _ = ContainerCliVersion::parse(&text);
        let _ = ImageInspection::parse(&text);
    }
}

/// The edit generator reaches both answers, so the implication above is not
/// vacuously true on either side.
#[test]
fn an_edit_can_be_either_refused_or_accepted() {
    let line = ContainerCliVersion::parse(REAL_CLI_LINE).unwrap().line();
    let mut accepted = line.clone();
    accepted.insert(line.find("1.4.1").unwrap(), '9');
    assert!(
        ContainerCliVersion::parse(&accepted).is_ok(),
        "an edit inside a component leaves a well-formed line"
    );
    let mut refused = line.clone();
    refused.insert(0, 'x');
    assert!(
        ContainerCliVersion::parse(&refused).is_err(),
        "an edit to the fixed text does not"
    );
}

// --- `container image inspect` ----------------------------------------------

#[test]
fn the_real_inspect_document_yields_the_label_and_the_resolved_digest() {
    let inspection = ImageInspection::parse(REAL_INSPECT).unwrap();
    assert_eq!(
        inspection.isolation_abi,
        Some(ImageIsolationAbi::Version(ISOLATION_ABI_VERSION))
    );
    assert_eq!(inspection.digest.as_str(), REAL_DIGEST);
}

/// One image object, `n` variants each carrying `labels`.
fn inspect_document(digest: &str, labels: &[Option<&str>]) -> String {
    let variants: Vec<String> = labels
        .iter()
        .map(|label| {
            let config = match label {
                None => "{}".to_string(),
                Some(value) => format!(r#"{{"Labels":{{"{ISOLATION_ABI_LABEL}":"{value}"}}}}"#),
            };
            format!(r#"{{"config":{{"architecture":"arm64","config":{config}}}}}"#)
        })
        .collect();
    format!(
        r#"[{{"configuration":{{"descriptor":{{"digest":"{digest}"}}}},"variants":[{}]}}]"#,
        variants.join(",")
    )
}

#[test]
fn variants_must_agree_about_the_label() {
    let two_v1 = inspect_document(REAL_DIGEST, &[Some("1"), Some("1")]);
    assert_eq!(
        ImageInspection::parse(&two_v1).unwrap().isolation_abi,
        Some(ImageIsolationAbi::Version(1))
    );

    let none = inspect_document(REAL_DIGEST, &[None, None]);
    assert_eq!(
        ImageInspection::parse(&none).unwrap().isolation_abi,
        Some(ImageIsolationAbi::Absent)
    );

    for disagreeing in [
        inspect_document(REAL_DIGEST, &[Some("1"), Some("2")]),
        inspect_document(REAL_DIGEST, &[Some("1"), None]),
        inspect_document(REAL_DIGEST, &[None, Some("1")]),
    ] {
        let inspection = ImageInspection::parse(&disagreeing).unwrap();
        assert_eq!(
            inspection.isolation_abi, None,
            "disagreeing variants name no single ABI"
        );
        assert_eq!(
            inspection.digest.as_str(),
            REAL_DIGEST,
            "an unreadable label leaves the digest readable"
        );
    }
}

#[test]
fn a_label_that_is_not_a_canonical_decimal_is_no_abi_at_all() {
    for value in ["", "one", "01", "+1", "1.0", " 1", "1 ", "-1", "4294967296"] {
        let document = inspect_document(REAL_DIGEST, &[Some(value)]);
        assert_eq!(
            ImageInspection::parse(&document).unwrap().isolation_abi,
            None,
            "read {value:?} as an ABI version"
        );
    }
}

#[test]
fn an_inspect_document_that_does_not_name_one_image_is_refused() {
    assert_eq!(
        ImageInspection::parse("[]"),
        Err(ImageInspectParseError::NotExactlyOneImage(0))
    );
    let one = inspect_document(REAL_DIGEST, &[Some("1")]);
    let body = one.trim_start_matches('[').trim_end_matches(']');
    assert_eq!(
        ImageInspection::parse(&format!("[{body},{body}]")),
        Err(ImageInspectParseError::NotExactlyOneImage(2)),
        "a tag that resolves to two images is not an identity"
    );
    assert_eq!(
        ImageInspection::parse(&inspect_document(REAL_DIGEST, &[])),
        Err(ImageInspectParseError::NoVariants)
    );
    assert_eq!(
        ImageInspection::parse(&inspect_document("sha256:nope", &[Some("1")])),
        Err(ImageInspectParseError::Digest(ImageDigestParseError))
    );
    for malformed in ["", "{}", "not json", "[{}]", "[1]"] {
        assert_eq!(
            ImageInspection::parse(malformed),
            Err(ImageInspectParseError::Malformed),
            "read {malformed:?} as an inspect document"
        );
    }
}

// --- the probe plan ---------------------------------------------------------

fn tool_paths() -> AgentVmToolPaths {
    AgentVmToolPaths::new(
        "/usr/local/bin/container",
        "/usr/local/libexec/helper",
        "/usr/bin/sudo",
    )
}

#[test]
fn the_plan_runs_the_privileged_helper_through_sudo_and_nothing_else_as_root() {
    let plan = LockedV1ProbePlan::for_host(
        &tool_paths(),
        &ContainerImage::new("writ-agent-vm-guest:latest").unwrap(),
    );
    assert_eq!(
        plan.helper_protocol.invocation.display_shell(),
        "/usr/bin/sudo /usr/local/libexec/helper protocol-version"
    );
    assert_eq!(
        plan.preflight.invocation.display_shell(),
        "/usr/bin/sudo /usr/local/libexec/helper preflight"
    );
    assert_eq!(
        plan.image_inspect.invocation.display_shell(),
        "/usr/local/bin/container image inspect writ-agent-vm-guest:latest"
    );
    assert_eq!(
        plan.container_cli.invocation.display_shell(),
        "/usr/local/bin/container --version"
    );
    assert_eq!(
        plan.macos_build.invocation.display_shell(),
        "/usr/bin/sw_vers -buildVersion"
    );
    for probe in plan.probes() {
        assert!(probe.byte_cap > 0, "every probe is capped");
        assert!(probe.timeout > Duration::ZERO, "every probe has a deadline");
    }
}

// --- the gatherer -----------------------------------------------------------

/// Which probe a fake tool invocation belongs to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Probe {
    HelperProtocol,
    Preflight,
    ImageInspect,
    ContainerCli,
    MacOsBuild,
}

impl Probe {
    const ALL: [Probe; 5] = [
        Probe::HelperProtocol,
        Probe::Preflight,
        Probe::ImageInspect,
        Probe::ContainerCli,
        Probe::MacOsBuild,
    ];

    /// The shell word the fake tool dispatches on.
    fn tag(self) -> &'static str {
        match self {
            Probe::HelperProtocol => "helper_protocol",
            Probe::Preflight => "preflight",
            Probe::ImageInspect => "image_inspect",
            Probe::ContainerCli => "container_cli",
            Probe::MacOsBuild => "macos_build",
        }
    }

    /// The facts this probe feeds, and whether it is the *only* source of
    /// them (`image inspect` feeds two).
    fn facts(self) -> &'static [LockedV1Fact] {
        match self {
            Probe::HelperProtocol => &[LockedV1Fact::HelperProtocol],
            Probe::Preflight => &[LockedV1Fact::Preflight],
            Probe::ImageInspect => &[LockedV1Fact::ImageIsolationAbi, LockedV1Fact::ImageDigest],
            Probe::ContainerCli => &[LockedV1Fact::ContainerCli],
            Probe::MacOsBuild => &[LockedV1Fact::MacOsBuild],
        }
    }

    /// This probe's entry in a plan.
    fn of_mut(self, plan: &mut LockedV1ProbePlan) -> &mut LockedV1Probe {
        match self {
            Probe::HelperProtocol => &mut plan.helper_protocol,
            Probe::Preflight => &mut plan.preflight,
            Probe::ImageInspect => &mut plan.image_inspect,
            Probe::ContainerCli => &mut plan.container_cli,
            Probe::MacOsBuild => &mut plan.macos_build,
        }
    }

    fn observed_failure(self, evidence: &LockedV1RuntimeEvidence) -> Vec<Option<ProbeFailure>> {
        fn unreadable<T>(observed: &Observed<T>) -> Option<ProbeFailure> {
            match observed {
                Observed::Unreadable(failure) => Some(*failure),
                Observed::Read(_) => None,
            }
        }
        match self {
            Probe::HelperProtocol => vec![unreadable(&evidence.helper_protocol)],
            Probe::Preflight => vec![unreadable(&evidence.preflight)],
            Probe::ImageInspect => vec![
                unreadable(&evidence.image_isolation_abi),
                unreadable(&evidence.image_digest),
            ],
            Probe::ContainerCli => vec![unreadable(&evidence.container_cli)],
            Probe::MacOsBuild => vec![unreadable(&evidence.macos_build)],
        }
    }
}

/// How the fake tool misbehaves for one probe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Fault {
    /// The tool itself never returns.
    Hangs,
    /// The tool forks the work that never returns and waits on it, so killing
    /// the tool alone would leave a descendant running — which is what the
    /// real `sudo` → helper → `pfctl` chain looks like.
    HangsForked,
    Floods,
    ExitsNonZero,
    PrintsGarbage,
    Missing,
}

impl Fault {
    /// The faults the sweep applies to every probe. `HangsForked` is not
    /// among them: what it is for is the process-group kill, which is a
    /// property of one shared code path and gets a test of its own rather
    /// than five copies, each paying a deadline.
    const ALL: [Fault; 5] = [
        Fault::Hangs,
        Fault::Floods,
        Fault::ExitsNonZero,
        Fault::PrintsGarbage,
        Fault::Missing,
    ];

    /// The file the forked hang's descendant records *its own* pid in,
    /// relative to the fake host's root.
    ///
    /// Its own, via `$$`, and not the parent's `$!`: a foreground child that
    /// names itself is both the shape the real `sudo` → helper → `pfctl`
    /// chain has and the one that does not depend on a shell's job-control
    /// bookkeeping, which is not uniform across the shells this suite runs
    /// under (a Nix build sandbox's `/bin/sh` left `$!` empty).
    const FORKED_PID_FILE: &'static str = "forked.pid";

    /// What the host observes when `probe` suffers this fault.
    ///
    /// A missing binary is the one case that depends on which probe: the two
    /// helper probes run it as an argument to `sudo`, so `sudo` starts fine
    /// and fails to exec — exactly as the real privileged path would — while
    /// `container` and `sw_vers` are the program itself, which never starts.
    fn expected(self, probe: Probe) -> ProbeFailure {
        match self {
            Fault::Hangs | Fault::HangsForked => ProbeFailure::TimedOut,
            Fault::Floods => ProbeFailure::OutputTooLarge,
            Fault::ExitsNonZero => ProbeFailure::Failed,
            Fault::PrintsGarbage => ProbeFailure::Unparseable,
            Fault::Missing => match probe {
                Probe::HelperProtocol | Probe::Preflight => ProbeFailure::Failed,
                Probe::ImageInspect | Probe::ContainerCli | Probe::MacOsBuild => {
                    ProbeFailure::Spawn
                }
            },
        }
    }
}

/// A host of fake tools: one script standing in for `container`, the PF
/// helper and `sw_vers`, plus a `sudo` that just runs what it is given.
struct FakeHost {
    dir: tempfile::TempDir,
    fault: Option<(Probe, Fault)>,
}

impl FakeHost {
    /// Every probe answers correctly, except `fault`, which misbehaves.
    fn new(fault: Option<(Probe, Fault)>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(
            root.join("helper_protocol.out"),
            format!("{}\n", PfHelperProtocolDoc::current().render()),
        )
        .unwrap();
        fs::write(
            root.join("preflight.out"),
            format!("{}\n", preflight_doc(clean_report()).render()),
        )
        .unwrap();
        fs::write(root.join("image_inspect.out"), REAL_INSPECT).unwrap();
        fs::write(root.join("container_cli.out"), format!("{REAL_CLI_LINE}\n")).unwrap();
        fs::write(root.join("macos_build.out"), format!("{REAL_BUILD}\n")).unwrap();

        let (fault_tag, fault_kind) = match fault {
            Some((probe, kind)) => (probe.tag(), format!("{kind:?}")),
            None => ("none", "None".to_string()),
        };
        write_executable_script(
            root,
            "tool",
            &format!(
                r#"#!/bin/sh
case "$1" in
  protocol-version) probe=helper_protocol ;;
  preflight) probe=preflight ;;
  image) probe=image_inspect ;;
  --version) probe=container_cli ;;
  -buildVersion) probe=macos_build ;;
  *) printf 'unexpected argv: %s\n' "$*" >&2; exit 64 ;;
esac
if [ "$probe" = "{fault_tag}" ]; then
  case "{fault_kind}" in
    Hangs) exec sleep 600 ;;
    HangsForked) sh -c 'printf "%s\n" "$$" > "{root}/{pid_file}"; exec sleep 600' ;;
    Floods) exec head -c 1000000 /dev/zero ;;
    ExitsNonZero) printf 'the probe failed\n' >&2; exit 3 ;;
    PrintsGarbage) printf 'not a document at all\n'; exit 0 ;;
  esac
fi
exec cat "{root}/$probe.out"
"#,
                root = root.display(),
                pid_file = Fault::FORKED_PID_FILE,
            ),
        );
        // Real `sudo` answers a command it cannot find with one short line and
        // exit 127, rather than letting the shell's own `exec` diagnostic out;
        // this stand-in does the same, so the `Missing` fault behind it is the
        // failed *command* the production path would see.
        write_executable_script(
            root,
            "sudo",
            "#!/bin/sh\nif [ ! -x \"$1\" ]; then\n  printf 'sudo: command not found\\n' >&2\n  exit 127\nfi\nexec \"$@\"\n",
        );

        Self { dir, fault }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// A `Missing` fault points the probe at a path that does not exist,
    /// which no script can express — so it is expressed as a tool path
    /// instead.
    fn tool_for(&self, probes: [Probe; 2]) -> PathBuf {
        match self.fault {
            Some((probe, Fault::Missing)) if probes.contains(&probe) => self.root().join("absent"),
            _ => self.root().join("tool"),
        }
    }

    fn tools(&self) -> AgentVmToolPaths {
        AgentVmToolPaths::new(
            self.tool_for([Probe::ImageInspect, Probe::ContainerCli]),
            self.tool_for([Probe::HelperProtocol, Probe::Preflight]),
            self.root().join("sudo"),
        )
    }

    /// The plan against these tools, with deadlines a test can wait for.
    ///
    /// Every probe gets a deadline far longer than it needs (per `CLAUDE.md`:
    /// a deadline this suite races is a deadline that lets scheduling latency
    /// decide the result). The single exception is the probe that is
    /// *deliberately* hanging, which has to be waited out — so only that one
    /// is shortened, and only enough that a cold spawn under load is still
    /// not mistaken for a hang.
    fn plan(&self) -> LockedV1ProbePlan {
        let mut plan = LockedV1ProbePlan::new(
            &self.tools(),
            &self.tool_for([Probe::MacOsBuild, Probe::MacOsBuild]),
            &ContainerImage::new("writ-agent-vm-guest:latest").unwrap(),
        );
        for probe in plan.probes_mut() {
            probe.timeout = Duration::from_secs(120);
        }
        if let Some((probe, Fault::Hangs | Fault::HangsForked)) = self.fault {
            probe.of_mut(&mut plan).timeout = Duration::from_secs(5);
        }
        plan
    }
}

/// The `Missing` fault distinguishes `container` from the helper only by
/// which tool path it breaks; `ImageInspect` and `ContainerCli` share the
/// `container` binary, as do `HelperProtocol` and `Preflight` the helper. A
/// missing binary therefore breaks its sibling too, which the assertions
/// below account for.
fn siblings(probe: Probe, fault: Fault) -> Vec<Probe> {
    if fault != Fault::Missing {
        return vec![probe];
    }
    match probe {
        Probe::ImageInspect | Probe::ContainerCli => vec![Probe::ImageInspect, Probe::ContainerCli],
        Probe::HelperProtocol | Probe::Preflight => vec![Probe::HelperProtocol, Probe::Preflight],
        Probe::MacOsBuild => vec![Probe::MacOsBuild],
    }
}

/// How long the forked-hang probe below is given before its deadline fires.
///
/// Long, deliberately. The test needs the probe's shell to have started its
/// descendant and recorded the pid *before* the deadline kills the group, and
/// the only thing standing between those is how promptly this machine
/// schedules two shells. A short deadline would make load, not the code under
/// test, decide the result — and the test costs this much wall clock only
/// because it is one scenario rather than five.
const FORKED_HANG_TIMEOUT: Duration = Duration::from_secs(15);

/// Wait for the forked hang to record its descendant's pid, up to `budget`.
///
/// Runs concurrently with the probe, so it has the probe's whole deadline to
/// see the file — there is no window in which a slow shell reads as a missing
/// descendant.
async fn forked_descendant_pid(pid_file: &Path, budget: Duration) -> Option<libc::pid_t> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Ok(recorded) = fs::read_to_string(pid_file)
            && let Ok(pid) = recorded.trim().parse::<libc::pid_t>()
        {
            return Some(pid);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Whether a pid still exists. Signal 0 delivers nothing; it only asks.
fn process_is_alive(pid: libc::pid_t) -> bool {
    // SAFETY: `kill` with signal 0 performs no action beyond the existence
    // and permission check, and takes no pointer arguments.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// A probe that *forks* the work that never returns loses the whole process
/// group at its deadline, not just the process the host spawned.
///
/// This is the shape the privileged probes really have — `sudo` wrapping the
/// helper wrapping `pfctl` — so a deadline that killed only the direct child
/// would leave a wedged `pfctl` holding the captured pipe open, accumulating
/// one orphan per refused start. The `exec sleep` fixture the sweep uses
/// cannot show this: there is no descendant to strand.
#[tokio::test]
async fn a_probe_that_forks_its_work_loses_the_whole_group_at_its_deadline() {
    let host = FakeHost::new(Some((Probe::MacOsBuild, Fault::HangsForked)));
    let mut plan = host.plan();
    plan.macos_build.timeout = FORKED_HANG_TIMEOUT;
    let pid_file = host.root().join(Fault::FORKED_PID_FILE);

    // The poller outlives the probe's own deadline, because the probe is the
    // last of five and its deadline does not start until the other four have
    // run. It returns the moment the pid appears, so the slack costs nothing
    // when the fixture works.
    let (evidence, pid) = tokio::join!(
        gather_locked_v1_evidence(&plan),
        forked_descendant_pid(&pid_file, FORKED_HANG_TIMEOUT + Duration::from_secs(30)),
    );

    assert_eq!(
        evidence.macos_build,
        Observed::Unreadable(ProbeFailure::TimedOut),
        "a forked hang is still a hang"
    );
    let pid = pid.unwrap_or_else(|| {
        panic!(
            "the forked hang recorded no descendant pid within {FORKED_HANG_TIMEOUT:?}.\n\
             tool script:\n{script}\n\
             pid file: {recorded:?}\n\
             directory: {listing:?}",
            script = fs::read_to_string(host.root().join("tool")).unwrap_or_default(),
            recorded = fs::read_to_string(&pid_file).ok(),
            listing = fs::read_dir(host.root())
                .map(|entries| entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
        )
    });

    // The SIGKILL is delivered asynchronously and the orphan is reaped by
    // init, so allow the exit to land; the probe itself has already returned.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while process_is_alive(pid) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the probe's descendant {pid} outlived the deadline that killed its group"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_healthy_host_yields_readable_facts_for_every_probe() {
    let host = FakeHost::new(None);
    let evidence = gather_locked_v1_evidence(&host.plan()).await;
    assert_eq!(
        evidence,
        LockedV1RuntimeEvidence {
            helper_protocol: Observed::Read(PfHelperProtocolDoc::current()),
            preflight: Observed::Read(preflight_doc(clean_report())),
            image_isolation_abi: Observed::Read(ImageIsolationAbi::Version(ISOLATION_ABI_VERSION)),
            image_digest: Observed::Read(ImageDigest::parse(REAL_DIGEST).unwrap()),
            container_cli: Observed::Read(ContainerCliVersion::parse(REAL_CLI_LINE).unwrap()),
            macos_build: Observed::Read(MacOsBuild::parse(REAL_BUILD).unwrap()),
        }
    );

    // Readable is not the same as admitted: with this host's real facts in an
    // allowlist, it admits; with the shipped (empty) one, it does not.
    let allowlist =
        ProvenPlatforms::new([
            ProvenPlatform::parse(REAL_CLI_LINE, REAL_BUILD, REAL_DIGEST).unwrap(),
        ]);
    ConfiguredIpv6Profile::Ipv4OnlyLockedV1
        .admit_locked(&evidence, &allowlist)
        .expect("a proven platform admits");
    assert!(
        ConfiguredIpv6Profile::Ipv4OnlyLockedV1
            .admit_locked(&evidence, &ProvenPlatforms::shipped())
            .is_err(),
        "the shipped allowlist proves no platform yet"
    );
}

/// Each probe, misbehaving each way: the fact it feeds becomes unreadable
/// with the matching reason, every other fact still reads, and the host never
/// admits.
///
/// The five probes of one fault kind run concurrently — they are independent
/// fake hosts, and one of the five faults is a probe that has to be waited
/// out — while the fault kinds run one after another, so the machine never
/// carries more than five of these at once.
#[tokio::test]
async fn a_misbehaving_probe_yields_an_unreadable_fact_and_never_an_admission() {
    let allowlist =
        ProvenPlatforms::new([
            ProvenPlatform::parse(REAL_CLI_LINE, REAL_BUILD, REAL_DIGEST).unwrap(),
        ]);
    for fault in Fault::ALL {
        let scenarios = Probe::ALL.map(|probe| async move {
            let host = FakeHost::new(Some((probe, fault)));
            let evidence = gather_locked_v1_evidence(&host.plan()).await;
            (probe, host, evidence)
        });
        for (probe, _host, evidence) in futures_util::future::join_all(scenarios).await {
            let broken = siblings(probe, fault);

            for other in Probe::ALL {
                let observed = other.observed_failure(&evidence);
                if broken.contains(&other) {
                    for failure in &observed {
                        assert_eq!(
                            *failure,
                            Some(fault.expected(other)),
                            "{probe:?}/{fault:?}: {other:?} reported {failure:?}"
                        );
                    }
                } else {
                    assert!(
                        observed.iter().all(Option::is_none),
                        "{probe:?}/{fault:?}: {other:?} was collateral damage: {observed:?}"
                    );
                }
            }

            let refused = ConfiguredIpv6Profile::Ipv4OnlyLockedV1
                .admit_locked(&evidence, &allowlist)
                .expect_err("a broken probe never admits");
            let broken_facts: Vec<LockedV1Fact> =
                broken.iter().flat_map(|p| p.facts()).copied().collect();
            assert!(
                broken_facts.contains(&refused.fact()),
                "{probe:?}/{fault:?}: refused naming {:?}, not one of {broken_facts:?}",
                refused.fact()
            );
        }
    }
}

/// A probe whose output is exactly its cap is not "too large": the bound is
/// on exceeding it, and a document that fits must be read.
#[tokio::test]
async fn output_at_exactly_the_cap_is_still_read() {
    let host = FakeHost::new(None);
    let mut plan = host.plan();
    plan.image_inspect.byte_cap = REAL_INSPECT.len();
    let evidence = gather_locked_v1_evidence(&plan).await;
    assert_eq!(
        evidence.image_digest,
        Observed::Read(ImageDigest::parse(REAL_DIGEST).unwrap())
    );

    plan.image_inspect.byte_cap = REAL_INSPECT.len() - 1;
    let evidence = gather_locked_v1_evidence(&plan).await;
    assert_eq!(
        evidence.image_digest,
        Observed::Unreadable(ProbeFailure::OutputTooLarge),
        "one byte over the cap is refused, not truncated and parsed"
    );
}
