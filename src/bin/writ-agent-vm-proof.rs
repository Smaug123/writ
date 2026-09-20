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

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_pf_helper_protocol::PfHelperCountersDoc;
use writ::agent_vm_proof::{DeniedFamily, DenyExpectation, grade_deny_window};

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
    }
    Ok(())
}

fn read_counters(path: &PathBuf) -> Result<PfHelperCountersDoc, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    Ok(PfHelperCountersDoc::parse(text.trim())
        .map_err(|e| format!("{} is not a counters document: {e}", path.display()))?)
}
