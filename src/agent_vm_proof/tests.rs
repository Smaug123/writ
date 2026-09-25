//! Tests for the vertical proof's counter grading.
//!
//! The oracle is Stage E3a's: the graded rise is the summed rise of the
//! family's interface-scoped denies and of nothing else, a window in which the
//! anchor was reloaded is refused rather than graded, and a missing rule is a
//! refusal rather than a reading of zero.

use proptest::prelude::*;

use super::*;
use writ_core::core::{PfCounterKey, PfCounters, PfInterface};

fn interface(name: &str) -> PfInterface {
    PfInterface::new(name).expect("a valid interface name")
}

fn key(label: &str, interface_name: Option<&str>) -> PfCounterKey {
    PfCounterKey::new(label, interface_name.map(interface)).expect("a label the grammar carries")
}

fn snapshot(entries: &[(PfCounterKey, u64)]) -> PfCounterSnapshot {
    PfCounterSnapshot::new(entries.iter().map(|(key, packets)| {
        (
            key.clone(),
            PfCounters {
                packets: *packets,
                bytes: *packets * 64,
            },
        )
    }))
    .expect("distinct keys")
}

/// Every interface the family is denied on contributes, and nothing else
/// does. The anchor installs one deny per family per interface and PF may
/// decide a frame on any of them, so a family is a set of rules and the
/// reading is their sum.
#[test]
fn the_reading_is_the_sum_over_every_interface_of_that_family_alone() {
    let v6_bridge = key(IPV6_IFACE_DENY_LABEL, Some("bridge100"));
    let v6_member = key(IPV6_IFACE_DENY_LABEL, Some("vmenet0"));
    let v4_bridge = key(IPV4_IFACE_DENY_LABEL, Some("bridge100"));
    let before = snapshot(&[
        (v6_bridge.clone(), 10),
        (v6_member.clone(), 100),
        (v4_bridge.clone(), 1000),
    ]);
    let after = snapshot(&[(v6_bridge, 13), (v6_member, 104), (v4_bridge, 2000)]);

    assert_eq!(
        grade_deny_window(
            &before,
            &after,
            DeniedFamily::Ipv6,
            DenyExpectation::RoseByAtLeast(7)
        ),
        Ok(DenyReading {
            packets: 7,
            rules: 2
        }),
        "the v6 denies rose by 3 and 4; the v4 rise of 1000 is another family"
    );
    assert_eq!(
        grade_deny_window(
            &before,
            &after,
            DeniedFamily::Ipv4,
            DenyExpectation::RoseByAtLeast(1000)
        ),
        Ok(DenyReading {
            packets: 1000,
            rules: 1
        })
    );
}

/// An anchor with no rule of the family counts nothing, and a rise of nothing
/// satisfies `Unmoved` perfectly. The absence of the rule is therefore a
/// refusal, not a reading.
#[test]
fn a_family_the_anchor_does_not_deny_is_refused_rather_than_read_as_zero() {
    let only_v4 = snapshot(&[(key(IPV4_IFACE_DENY_LABEL, Some("bridge100")), 0)]);
    for expected in [DenyExpectation::Unmoved, DenyExpectation::RoseByAtLeast(0)] {
        assert_eq!(
            grade_deny_window(&only_v4, &only_v4, DeniedFamily::Ipv6, expected),
            Err(DenyRefusal::NoSuchDeny {
                family: DeniedFamily::Ipv6,
                label: IPV6_IFACE_DENY_LABEL,
            }),
            "{expected:?}"
        );
    }
}

/// A rule carrying the interface-deny label but scoped to no interface is
/// not an interface-scoped deny, and must not be counted as one.
///
/// The real helper cannot produce that pairing — it files a subnet-scoped
/// deny under a different label — but the grader reads a *file*, and the wire
/// format admits it. Counting it would let a document with no interface deny
/// in it satisfy `Unmoved` perfectly, which is the one reading this grading
/// exists to refuse.
#[test]
fn a_deny_scoped_to_no_interface_is_not_an_interface_deny() {
    let unscoped = key(IPV6_IFACE_DENY_LABEL, None);
    let only_unscoped = snapshot(&[(unscoped.clone(), 0)]);
    assert_eq!(
        grade_deny_window(
            &only_unscoped,
            &only_unscoped,
            DeniedFamily::Ipv6,
            DenyExpectation::Unmoved
        ),
        Err(DenyRefusal::NoSuchDeny {
            family: DeniedFamily::Ipv6,
            label: IPV6_IFACE_DENY_LABEL,
        }),
        "an unscoped rule is not the rule this window is about"
    );

    // And beside a real one, it contributes nothing to the reading.
    let scoped = key(IPV6_IFACE_DENY_LABEL, Some("bridge100"));
    let before = snapshot(&[(unscoped.clone(), 0), (scoped.clone(), 0)]);
    let after = snapshot(&[(unscoped, 500), (scoped, 2)]);
    assert_eq!(
        grade_deny_window(
            &before,
            &after,
            DeniedFamily::Ipv6,
            DenyExpectation::RoseByAtLeast(2)
        ),
        Ok(DenyReading {
            packets: 2,
            rules: 1
        })
    );
}

/// Two readings of *different* anchors are not a measurement, and the typed
/// read is what makes that sayable: the `awk` this replaces could only
/// subtract two numbers and get a plausible one.
#[test]
fn a_window_in_which_the_anchor_was_reloaded_is_refused_rather_than_graded() {
    let bridge = key(IPV6_IFACE_DENY_LABEL, Some("bridge100"));
    let member = key(IPV6_IFACE_DENY_LABEL, Some("vmenet0"));

    // The anchor was reloaded and its counters restarted.
    let before = snapshot(&[(bridge.clone(), 40)]);
    let after = snapshot(&[(bridge.clone(), 3)]);
    assert!(
        matches!(
            grade_deny_window(
                &before,
                &after,
                DeniedFamily::Ipv6,
                DenyExpectation::RoseByAtLeast(1)
            ),
            Err(DenyRefusal::NotOneAnchor(
                PfCounterDeltaError::Decreased { .. }
            ))
        ),
        "a counter that fell means the anchor was reloaded between the readings"
    );

    // The anchor was reloaded and gained an interface.
    let after = snapshot(&[(bridge, 40), (member, 0)]);
    assert!(matches!(
        grade_deny_window(
            &before,
            &after,
            DeniedFamily::Ipv6,
            DenyExpectation::Unmoved
        ),
        Err(DenyRefusal::NotOneAnchor(
            PfCounterDeltaError::KeySetsDiffer { .. }
        ))
    ));
}

/// The two expectations are exact about what they accept, and a refusal
/// carries the reading it saw so a failed proof says what it measured.
#[test]
fn each_expectation_accepts_exactly_what_it_says() {
    let bridge = key(IPV6_IFACE_DENY_LABEL, Some("bridge100"));
    let before = snapshot(&[(bridge.clone(), 7)]);

    for (rise, unmoved_ok, at_least_three_ok) in [
        (0u64, true, false),
        (1, false, false),
        (3, false, true),
        (9, false, true),
    ] {
        let after = snapshot(&[(bridge.clone(), 7 + rise)]);
        let observed = DenyReading {
            packets: rise,
            rules: 1,
        };
        assert_eq!(
            grade_deny_window(
                &before,
                &after,
                DeniedFamily::Ipv6,
                DenyExpectation::Unmoved
            )
            .is_ok(),
            unmoved_ok,
            "Unmoved against a rise of {rise}"
        );
        let at_least_three = grade_deny_window(
            &before,
            &after,
            DeniedFamily::Ipv6,
            DenyExpectation::RoseByAtLeast(3),
        );
        assert_eq!(
            at_least_three.is_ok(),
            at_least_three_ok,
            "RoseByAtLeast(3) against a rise of {rise}"
        );
        if let Err(refusal) = at_least_three {
            assert_eq!(
                refusal,
                DenyRefusal::Unmet {
                    family: DeniedFamily::Ipv6,
                    expected: DenyExpectation::RoseByAtLeast(3),
                    observed,
                },
                "a refusal carries what it measured"
            );
        }
    }
}

/// Each family reads its own label, and the labels are the ones the firewall
/// renders. A grader looking for a label nothing emits would find no rule,
/// and "no rule" is a refusal it could not tell from a genuine one.
#[test]
fn each_family_reads_the_label_the_firewall_renders() {
    assert_eq!(DeniedFamily::Ipv4.label(), IPV4_IFACE_DENY_LABEL);
    assert_eq!(DeniedFamily::Ipv6.label(), IPV6_IFACE_DENY_LABEL);
    assert_ne!(DeniedFamily::Ipv4.label(), DeniedFamily::Ipv6.label());
}

proptest! {
    /// Over any pair of readings of one anchor: the graded rise is the sum of
    /// the family's own keys, whatever else the anchor counts.
    ///
    /// Stated over the whole snapshot rather than over a handful of cases,
    /// because "and of nothing else" is a claim about every other key there
    /// could be.
    #[test]
    fn the_graded_rise_is_the_family_sum_and_no_other_keys_contribute(
        v6 in prop::collection::vec((0u64..1000, 0u64..1000), 1..4),
        v4 in prop::collection::vec((0u64..1000, 0u64..1000), 0..4),
    ) {
        let entry = |label: &str, n: usize, (base, rise): (u64, u64)| {
            let k = key(label, Some(&format!("vmenet{n}")));
            ((k.clone(), base), (k, base + rise))
        };
        let mut before = Vec::new();
        let mut after = Vec::new();
        let mut expected_rise = 0u64;
        let mut expected_rules = 0usize;
        for (n, pair) in v6.iter().enumerate() {
            let (b, a) = entry(IPV6_IFACE_DENY_LABEL, n, *pair);
            expected_rise += pair.1;
            expected_rules += 1;
            before.push(b);
            after.push(a);
        }
        for (n, pair) in v4.iter().enumerate() {
            let (b, a) = entry(IPV4_IFACE_DENY_LABEL, n, *pair);
            before.push(b);
            after.push(a);
        }

        let graded = grade_deny_window(
            &snapshot(&before),
            &snapshot(&after),
            DeniedFamily::Ipv6,
            DenyExpectation::RoseByAtLeast(expected_rise),
        );
        prop_assert_eq!(
            graded,
            Ok(DenyReading { packets: expected_rise, rules: expected_rules })
        );
    }
}
