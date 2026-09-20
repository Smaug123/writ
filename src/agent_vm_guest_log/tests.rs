//! Tests for the host's read side of the locked guest's record channel.
//!
//! Two oracles, from Stage E2 of
//! `docs/plans/2026-09-01-ipv4-only-locked-v1.md`:
//!
//! 1. Over fuzzed `container logs` output, only a line that is exactly a
//!    rendered record is read as one, and only a lone `security-ready` record
//!    naming this host's ABI releases. Noise around a record does not change
//!    what it says; a second record, a prefixed line that is not a record, and
//!    an over-long one are each refused rather than skipped.
//! 2. Against a fake `container`, the wait is bounded and fails closed in
//!    every direction a tool can fail: a silent guest, a flooding one, a
//!    wedged tool, a tool that exits non-zero, a reported handoff failure.
//!    The one success yields the facts Stage E1's `guest_security_locked`
//!    takes.

use std::fs;
use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::test_support::write_executable_script;
use writ_guest_init::record::{MAX_RECORD_BYTES, SECURITY_READY_LINE};

// --- generators -------------------------------------------------------------

/// The line a correct initializer on this host emits.
fn ready_line() -> String {
    GuestInitRecord::SecurityReady {
        abi: ISOLATION_ABI_VERSION,
    }
    .render()
}

/// A message that survives a render/parse round trip: no control bytes, and
/// short enough that the whole record stays under the record bound.
fn any_message() -> impl Strategy<Value = BoundedMessage> {
    r"[^\p{Cc}]{0,60}".prop_map(|text| BoundedMessage::new(&text))
}

fn any_record() -> impl Strategy<Value = GuestInitRecord> {
    prop_oneof![
        any::<u32>().prop_map(|abi| GuestInitRecord::SecurityReady { abi }),
        (any::<usize>(), any_message()).prop_map(|(step_index, message)| {
            GuestInitRecord::HandoffFailed {
                step_index,
                message,
            }
        }),
    ]
}

/// A line the initializer did not write: no newline, and not wearing the
/// record prefix.
fn any_noise_line() -> impl Strategy<Value = String> {
    r"[^\n]{0,60}".prop_filter("not a record line", |line: &String| {
        !line
            .strip_suffix('\r')
            .unwrap_or(line)
            .starts_with(RECORD_PREFIX)
    })
}

/// A line wearing the record prefix that is not a record this host reads.
fn any_malformed_record_line() -> impl Strategy<Value = String> {
    r"[^\n]{0,80}"
        .prop_map(|tail: String| format!("{RECORD_PREFIX} {tail}"))
        .prop_filter("not parseable as a record", |line: &String| {
            GuestInitRecord::parse(line).is_err()
        })
}

/// Splice `record` into `noise` at `position`, and give back the log text.
fn log_with(noise: &[String], record: &str, position: usize) -> String {
    let mut lines: Vec<String> = noise.to_vec();
    let at = if lines.is_empty() {
        0
    } else {
        position % (lines.len() + 1)
    };
    lines.insert(at, record.to_string());
    lines.join("\n")
}

// --- the pure scan ----------------------------------------------------------

proptest! {
    /// A record alone on a line is read back as itself, whatever the guest
    /// put around it.
    #[test]
    fn a_lone_record_is_read_back_through_any_noise(
        record in any_record(),
        noise in prop::collection::vec(any_noise_line(), 0..6),
        position in 0usize..8,
    ) {
        let text = log_with(&noise, &record.render(), position);
        let expected = match &record {
            GuestInitRecord::SecurityReady { abi } => {
                GuestHandoffReport::Ready(GuestFacts::new(*abi))
            }
            GuestInitRecord::HandoffFailed { step_index, message } => {
                GuestHandoffReport::Failed {
                    step_index: *step_index,
                    message: message.clone(),
                }
            }
        };
        prop_assert_eq!(scan_guest_log(&text), Ok(expected));
    }

    /// A log with nothing of ours in it says nothing. The reader must not
    /// invent a report out of a guest's ordinary chatter.
    #[test]
    fn a_log_without_a_record_is_silent(
        noise in prop::collection::vec(any_noise_line(), 0..8),
    ) {
        prop_assert_eq!(
            scan_guest_log(&noise.join("\n")),
            Ok(GuestHandoffReport::Silent)
        );
    }

    /// A line wearing the prefix that is not a record is a disagreement about
    /// the handoff contract, so it is refused rather than skipped past — even
    /// when a valid record sits beside it.
    #[test]
    fn a_prefixed_line_that_is_not_a_record_is_refused(
        malformed in any_malformed_record_line(),
        record in any_record(),
        noise in prop::collection::vec(any_noise_line(), 0..4),
        position in 0usize..8,
        with_record in any::<bool>(),
    ) {
        let mut lines = noise;
        if with_record {
            lines.push(record.render());
        }
        let text = log_with(&lines, &malformed, position);
        let scanned = scan_guest_log(&text);
        prop_assert!(
            matches!(scanned, Err(GuestLogScanError::Malformed { .. })),
            "{scanned:?}"
        );
    }

    /// Two records mean something other than the initializer is writing to
    /// the channel, whichever two they are — including two identical ready
    /// records, which is the shape a replayed log would have.
    #[test]
    fn two_records_are_refused_however_they_are_spelled(
        first in any_record(),
        second in any_record(),
        noise in prop::collection::vec(any_noise_line(), 0..4),
        position in 0usize..8,
    ) {
        let mut lines = noise;
        lines.push(second.render());
        let text = log_with(&lines, &first.render(), position);
        prop_assert_eq!(
            scan_guest_log(&text),
            Err(GuestLogScanError::Repeated { count: 2 })
        );
    }

    /// One trailing carriage return is the transport's, not the record's: a
    /// runtime that hands the guest a terminal must not make a correct
    /// initializer unreadable.
    #[test]
    fn a_trailing_carriage_return_does_not_hide_a_record(record in any_record()) {
        let with_cr = format!("{}\r\n", record.render());
        prop_assert_eq!(scan_guest_log(&with_cr), scan_guest_log(&record.render()));
    }
}

/// An over-long line wearing the prefix is refused unread, at the record
/// bound rather than at whatever the parser would have made of a prefix of
/// it.
#[test]
fn an_over_long_record_is_refused() {
    let padded = format!(
        "{} {}",
        GuestInitRecord::SecurityReady { abi: 1 }.render(),
        "x".repeat(MAX_RECORD_BYTES)
    );
    assert!(matches!(
        scan_guest_log(&padded),
        Err(GuestLogScanError::Malformed {
            source: RecordParseError::TooLong { .. },
            ..
        })
    ));
}

/// A record must begin its line. Accepting one embedded in a longer line
/// would hand the framing to whoever wrote the line, and the record's own
/// bounds would stop bounding anything.
#[test]
fn a_record_embedded_in_a_longer_line_is_not_a_record() {
    let embedded = format!("2026-09-20T12:00:00Z {}", ready_line());
    assert_eq!(scan_guest_log(&embedded), Ok(GuestHandoffReport::Silent));
}

/// The reported failure is not a report of readiness: confusing the two is
/// what would release a guest whose handoff never completed.
#[test]
fn a_handoff_failure_is_not_a_ready_report() {
    let failed = GuestInitRecord::HandoffFailed {
        step_index: 4,
        message: BoundedMessage::new("sysctl write refused"),
    };
    assert_eq!(
        scan_guest_log(&failed.render()),
        Ok(GuestHandoffReport::Failed {
            step_index: 4,
            message: BoundedMessage::new("sysctl write refused"),
        })
    );
}

/// The host reads the line the guest crate spells out, not merely the one its
/// own `render` produces: the two crates agree on the wire form or the
/// release gate never opens.
#[test]
fn the_spelled_out_ready_line_is_read_as_ready() {
    assert_eq!(
        scan_guest_log(SECURITY_READY_LINE),
        Ok(GuestHandoffReport::Ready(GuestFacts::new(
            ISOLATION_ABI_VERSION
        )))
    );
}

proptest! {
    /// The sleep between reads never outlasts what is left of the budget, and
    /// never exceeds the poll interval. Stated over every combination of the
    /// three, because it is the whole of "`overall_timeout` bounds the wait"
    /// and it is pure — timing the real loop would measure spawn latency.
    #[test]
    fn next_poll_sleep_never_outlasts_the_budget(
        poll_ms in 0u64..100_000,
        budget_ms in 0u64..100_000,
        elapsed_ms in 0u64..100_000,
    ) {
        let channel = GuestLogChannel::new(Path::new("/nonexistent"), "vm")
            .with_wait_bounds_for_test(
                Duration::from_millis(poll_ms),
                Duration::from_millis(budget_ms),
            );
        let left = Duration::from_millis(budget_ms)
            .saturating_sub(Duration::from_millis(elapsed_ms));
        let sleep = channel.next_poll_sleep(Duration::from_millis(elapsed_ms));
        prop_assert!(sleep <= left, "{sleep:?} > {left:?} left");
        prop_assert!(sleep <= Duration::from_millis(poll_ms));
    }
}

// --- the bounded reader -----------------------------------------------------

/// A fake `container` whose `logs` answers from a file, and which records
/// every argv it was given.
struct FakeContainer {
    dir: tempfile::TempDir,
}

impl FakeContainer {
    /// `body` is the shell that answers `container logs`; it may consult
    /// `$root` for state.
    fn new(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_executable_script(
            root,
            "container",
            &format!(
                r#"#!/bin/sh
root="{root}"
printf '%s\n' "$*" >> "$root/argv.log"
if [ "$1" != "logs" ]; then
  printf 'unexpected argv: %s\n' "$*" >&2
  exit 64
fi
{body}
"#,
                root = root.display(),
            ),
        );
        Self { dir }
    }

    /// A fake whose log is a fixed string.
    fn printing(log: &str) -> Self {
        let fake = Self::new("exec cat \"$root/log.out\"");
        fs::write(fake.root().join("log.out"), log).unwrap();
        fake
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The channel against this fake. The budget is far longer than any test
    /// here needs, because every test but the silence one ends at its first
    /// read: a budget that a slow process spawn could exhaust would let load,
    /// not the code, decide the result. The per-read cap and deadline stay
    /// production-sized — the one test that shortens the deadline is waiting
    /// out a deliberate hang.
    fn channel(&self) -> GuestLogChannel {
        GuestLogChannel::new(&self.root().join("container"), "writ-agent-vm-test")
            .with_wait_bounds_for_test(Duration::from_millis(5), Duration::from_secs(60))
    }

    fn argv_lines(&self) -> Vec<String> {
        fs::read_to_string(self.root().join("argv.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// The host asks for the whole stdio log of one VM and nothing else. `-n`
/// would keep the wrong end (a flooding guest could push the record out of
/// the window and be read as silent) and `--boot` is a different stream.
#[test]
fn the_host_asks_for_the_whole_stdio_log_of_one_vm() {
    let channel = GuestLogChannel::new(Path::new("/usr/local/bin/container"), "writ-agent-vm-abc");
    assert_eq!(
        channel.probe().invocation.args_lossy(),
        vec!["logs".to_string(), "writ-agent-vm-abc".to_string()]
    );
}

#[tokio::test]
async fn a_ready_record_naming_this_hosts_abi_releases() {
    let fake = FakeContainer::printing(&format!("boot noise\n{}\n", ready_line()));
    let facts = fake.channel().await_security_ready().await.unwrap();
    assert_eq!(facts, GuestFacts::new(ISOLATION_ABI_VERSION));
    assert_eq!(fake.argv_lines(), vec!["logs writ-agent-vm-test"]);
}

/// The record the *running* initializer announced is a separate fact from the
/// label Stage D read off the image, and a host that does not implement the
/// announced ABI does not know what it would be releasing.
#[tokio::test]
async fn an_abi_this_host_does_not_implement_does_not_release() {
    let line = GuestInitRecord::SecurityReady {
        abi: ISOLATION_ABI_VERSION + 1,
    }
    .render();
    let fake = FakeContainer::printing(&format!("{line}\n"));
    assert_eq!(
        fake.channel().await_security_ready().await,
        Err(SecurityReadyError::AbiVersion {
            host: ISOLATION_ABI_VERSION,
            guest: ISOLATION_ABI_VERSION + 1,
        })
    );
}

/// A record that only appears on a later read is still read: the wait polls
/// rather than taking one look.
#[tokio::test]
async fn a_record_that_appears_later_is_still_read() {
    // One `x` per read, counted with `case` rather than `wc`: the Nix build
    // sandbox's `/bin/sh` runs this suite too, and `cat` is the only counting
    // tool this file already relies on being there.
    let fake = FakeContainer::new(
        r#"printf 'x' >> "$root/reads"
case "$(cat "$root/reads")" in
  xxx*) exec cat "$root/log.out" ;;
esac
exit 0"#,
    );
    fs::write(fake.root().join("log.out"), ready_line()).unwrap();
    let facts = fake.channel().await_security_ready().await.unwrap();
    assert_eq!(facts, GuestFacts::new(ISOLATION_ABI_VERSION));
    assert!(fake.argv_lines().len() >= 3);
}

/// A reported handoff failure ends the wait at once and carries the
/// initializer's own bounded reason: there is no workload to release, and the
/// operator wants the step that failed.
#[tokio::test]
async fn a_reported_handoff_failure_ends_the_wait() {
    let line = GuestInitRecord::HandoffFailed {
        step_index: 5,
        message: BoundedMessage::new("bounding set entry survived"),
    }
    .render();
    let fake = FakeContainer::printing(&format!("{line}\n"));
    assert_eq!(
        fake.channel().await_security_ready().await,
        Err(SecurityReadyError::HandoffFailed {
            step_index: 5,
            message: "bounding set entry survived".to_string(),
        })
    );
}

/// A guest that says nothing is not released, and the wait ends on the
/// host's clock rather than the guest's.
///
/// `Silent` is the answer down both of the paths a short budget can take —
/// reads that complete and report nothing, or a last read the budget cuts
/// short — which is what makes this assertion hold however loaded the machine
/// is. That the wait *polls* rather than taking one look is asserted by
/// `a_record_that_appears_later_is_still_read`, and that its sleep is bounded
/// by `next_poll_sleep_never_outlasts_the_budget`; neither needs this test to
/// win a race against a process spawn.
#[tokio::test]
async fn a_silent_guest_is_not_released() {
    let fake = FakeContainer::printing("nothing to see\n");
    let timeout = Duration::from_secs(3);
    let channel = fake
        .channel()
        .with_wait_bounds_for_test(Duration::from_millis(5), timeout);
    assert_eq!(
        channel.await_security_ready().await,
        Err(SecurityReadyError::Silent { timeout })
    );
}

/// A guest that floods the pre-release channel is refused rather than read in
/// part: the record that would have refused could be the part that was cut.
#[tokio::test]
async fn a_flooding_guest_is_refused_rather_than_read_in_part() {
    let fake = FakeContainer::new("exec head -c 1000000 /dev/zero");
    assert_eq!(
        fake.channel().await_security_ready().await,
        Err(SecurityReadyError::Unread(ProbeRunFailure::OutputTooLarge))
    );
}

/// A wedged `container logs` is killed at the read deadline, and the wait
/// reports that it read nothing rather than waiting out the whole release
/// budget in one tick.
#[tokio::test]
async fn a_wedged_log_read_is_killed_at_its_deadline() {
    let fake = FakeContainer::new("exec sleep 600");
    // The one deadline this suite deliberately races: the tool is *meant* to
    // hang, so it has to be waited out. Long enough that a cold spawn under
    // load is not mistaken for the hang.
    let channel = fake
        .channel()
        .with_read_bounds_for_test(Duration::from_secs(2));
    assert_eq!(
        channel.await_security_ready().await,
        Err(SecurityReadyError::Unread(ProbeRunFailure::TimedOut))
    );
}

/// A `container logs` that fails is not a silent guest: the host does not
/// know what the guest said, so it stops rather than polling out the budget
/// against a tool that is not working.
#[tokio::test]
async fn a_log_tool_that_fails_stops_the_wait() {
    let fake = FakeContainer::new("printf 'no such container\\n' >&2; exit 1");
    assert_eq!(
        fake.channel().await_security_ready().await,
        Err(SecurityReadyError::Unread(ProbeRunFailure::Failed))
    );
}

/// A `container` that is not there at all is a spawn failure, not a silent
/// guest.
#[tokio::test]
async fn a_missing_container_tool_stops_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let channel = GuestLogChannel::new(&dir.path().join("absent"), "writ-agent-vm-test")
        .with_wait_bounds_for_test(Duration::from_millis(5), Duration::from_secs(60));
    assert_eq!(
        channel.await_security_ready().await,
        Err(SecurityReadyError::Unread(ProbeRunFailure::Spawn))
    );
}

/// A log that says two things stops the wait rather than being retried: it
/// does not stop having said them.
#[tokio::test]
async fn a_log_that_says_two_things_stops_the_wait() {
    let fake = FakeContainer::printing(&format!("{}\n{}\n", ready_line(), ready_line()));
    assert_eq!(
        fake.channel().await_security_ready().await,
        Err(SecurityReadyError::Unreadable(
            GuestLogScanError::Repeated { count: 2 }
        ))
    );
}
