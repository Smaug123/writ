//! The unprivileged grader `scripts/prove-*.sh` shells to.
//!
//! The proof harness is shell, and the facts it grades on are typed documents
//! the privileged helper prints. Rather than teach shell to read them — which
//! is the `awk` this replaces — the harness hands both readings here and is
//! told what they mean.
//!
//! Deliberately **unprivileged**, and deliberately not part of the helper: the
//! helper runs under `sudo` and its job is to read PF, while this decides what
//! a reading means. A grader that ran as root would be a second privileged
//! surface for no reason, and one built into the helper would let a proof's
//! expectations be argued with the thing being measured.
//!
//! The harness never reads the guest's answers itself: it captures them into
//! a directory, and `guest-report` is the one reader, holding each as a claim
//! that can withdraw the verdict and never reach one.

use std::io::Read as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_pf_helper_protocol::PfHelperCountersDoc;
use writ::agent_vm_proof::guest::{GuestReport, GuestSlot, SessionVerdict, grade_guest_report};
use writ::agent_vm_proof::listener::{ListenerExpectation, grade_listener_log};
use writ::agent_vm_proof::{DeniedFamily, DenyExpectation, grade_deny_window};
use writ_core::core::Ipv4Cidr;

#[derive(Parser)]
#[command(name = "writ-agent-vm-proof", about = "writ agent VM proof grading")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Grade what one session anchor's interface-scoped denies of one family
    /// counted between two readings, against what the profile under test
    /// requires. Prints the reading on success; names what it measured, and
    /// why that is not enough, on failure.
    DenyWindow(DenyWindowArgs),
    /// Grade what a listener the host runs logged: that it served a path to
    /// one peer, or that no peer in a subnet reached it at all.
    ListenerLog(ListenerLogArgs),
    /// Print the guest's address on a network, from `container inspect` JSON
    /// on stdin: the address the container runtime allocated, which the host
    /// holds, rather than the one the guest says it has.
    GuestAddress(GuestAddressArgs),
    /// Print every answer the guest gave as an untrusted appendix, and apply
    /// them as doubts to the verdict of the host-graded legs. The harness
    /// calls this only once every host-graded leg has passed, so the verdict
    /// it brings is `Proven`, and this exits non-zero if any answer withdraws
    /// it.
    GuestReport(GuestReportArgs),
}

#[derive(Args)]
struct ListenerLogArgs {
    /// The listener's access log.
    #[arg(long)]
    log: PathBuf,
    /// The listener must have answered `GET <path>` with 200 to this peer.
    #[arg(long, requires = "path", conflicts_with = "silent_to")]
    served_to: Option<Ipv4Addr>,
    #[arg(long, requires = "served_to")]
    path: Option<String>,
    /// No address in this subnet may appear anywhere in the log.
    #[arg(
        long,
        conflicts_with = "served_to",
        required_unless_present = "served_to"
    )]
    silent_to: Option<Ipv4Cidr>,
}

#[derive(Args)]
struct GuestAddressArgs {
    /// The container network whose attachment to read.
    #[arg(long)]
    network: String,
}

#[derive(Args)]
struct GuestReportArgs {
    /// The directory `guest_report` captured into: one `<slot>.txt` per
    /// question.
    #[arg(long)]
    dir: PathBuf,
    /// A slot whose doubt the harness has already accounted for — the broker
    /// fetch, when the positive control was waived. It still withdraws the
    /// verdict; naming it only makes this exit 3 rather than 1 when it is the
    /// *only* answer that does, so the harness can tell the waiver it asked
    /// for from a guest answer it did not expect. Not 2, which is clap's exit
    /// for a usage error — a misspelt slot, which grades nothing.
    #[arg(long, value_parser = parse_slot)]
    waived: Vec<GuestSlot>,
}

fn parse_slot(name: &str) -> Result<GuestSlot, String> {
    GuestSlot::from_name(name).ok_or_else(|| format!("{name:?} is not a guest report slot"))
}

#[derive(Args)]
struct DenyWindowArgs {
    /// The `counters` document read before the window.
    #[arg(long)]
    before: PathBuf,
    /// The `counters` document read after it.
    #[arg(long)]
    after: PathBuf,
    #[arg(long, value_enum)]
    family: Family,
    /// The counter must have risen by at least this many packets.
    #[arg(long, conflicts_with = "unmoved", required_unless_present = "unmoved")]
    rose_by_at_least: Option<u64>,
    /// The counter must not have moved at all.
    #[arg(long, conflicts_with = "rose_by_at_least")]
    unmoved: bool,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum Family {
    Ipv4,
    Ipv6,
}

impl From<Family> for DeniedFamily {
    fn from(family: Family) -> Self {
        match family {
            Family::Ipv4 => Self::Ipv4,
            Family::Ipv6 => Self::Ipv6,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::DenyWindow(args) => {
            let expected = match (args.rose_by_at_least, args.unmoved) {
                (Some(least), false) => DenyExpectation::RoseByAtLeast(least),
                (None, true) => DenyExpectation::Unmoved,
                // clap's `conflicts_with` and `required_unless_present` make
                // both other combinations unreachable, and saying so here
                // beats an `unreachable!` that would be a panic if either
                // attribute were ever edited away.
                _ => {
                    return Err(
                        "exactly one of --rose-by-at-least and --unmoved is required".into(),
                    );
                }
            };
            let before = read_counters(&args.before)?;
            let after = read_counters(&args.after)?;
            if before.session_id() != after.session_id() {
                return Err(format!(
                    "the two readings are of different sessions: {} then {}",
                    before.session_id(),
                    after.session_id()
                )
                .into());
            }
            let reading = grade_deny_window(
                before.snapshot(),
                after.snapshot(),
                args.family.into(),
                expected,
            )?;
            println!(
                "{:?} denies counted {} packet(s) across {} rule(s) in {}",
                DeniedFamily::from(args.family),
                reading.packets,
                reading.rules,
                before.anchor().as_str()
            );
        }
        Cmd::ListenerLog(args) => {
            let expected = match (args.served_to, args.path, args.silent_to) {
                (Some(peer), Some(path), None) => ListenerExpectation::Served { peer, path },
                (None, None, Some(peers)) => ListenerExpectation::Silent { peers },
                // As for `deny-window`: clap's attributes make these
                // unreachable, and an error beats a panic if they are edited.
                _ => {
                    return Err(
                        "exactly one of --served-to (with --path) and --silent-to is required"
                            .into(),
                    );
                }
            };
            let log = std::fs::read_to_string(&args.log)
                .map_err(|e| format!("could not read {}: {e}", args.log.display()))?;
            let served = grade_listener_log(&log, &expected)?;
            match expected {
                ListenerExpectation::Served { peer, path } => {
                    println!("the listener answered GET {path} to {peer} {served} time(s)");
                }
                ListenerExpectation::Silent { peers } => {
                    println!("the listener logged nothing from {peers}");
                }
            }
        }
        Cmd::GuestAddress(args) => {
            let mut inspect = String::new();
            std::io::stdin().read_to_string(&mut inspect)?;
            let address = writ::broker_vm::parse_broker_ipv4_on_network(&inspect, &args.network)?;
            println!("{address}");
        }
        Cmd::GuestReport(args) => {
            let report = GuestReport::read_dir(&args.dir)?;
            // The appendix is printed through `Debug`, so each answer is one
            // escaped line: a guest cannot print a newline and a line of its
            // own that reads like the harness's.
            println!("guest answers (untrusted diagnostics, never evidence):");
            for slot in GuestSlot::ALL {
                println!("  {}: {:?}", slot.name(), report.claim(slot));
            }
            let graded = grade_guest_report(SessionVerdict::Proven, &report);
            match graded.verdict {
                SessionVerdict::Proven => {
                    println!("no guest answer doubts the host-graded verdict");
                }
                SessionVerdict::Inconclusive => {
                    let names: Vec<&str> =
                        graded.doubted_by.iter().map(|slot| slot.name()).collect();
                    if graded
                        .doubted_by
                        .iter()
                        .all(|slot| args.waived.contains(slot))
                    {
                        eprintln!(
                            "error: the host-graded verdict is withdrawn, only by waived answers: {}",
                            names.join(", ")
                        );
                        std::process::exit(3);
                    }
                    return Err(format!(
                        "the guest's answers to {} are not what a passing run gives, so the \
                         host-graded verdict is withdrawn: inconclusive is failure",
                        names.join(", ")
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn read_counters(path: &PathBuf) -> Result<PfHelperCountersDoc, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    Ok(PfHelperCountersDoc::parse(text.trim())
        .map_err(|e| format!("{} is not a counters document: {e}", path.display()))?)
}
