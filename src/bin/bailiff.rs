//! `bailiff` — the workflow orchestrator that will eventually drive
//! plan/review/execute on top of writ's `RunAgent` RPC. See
//! `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! Slice A2 skeleton: the binary exists, connects to writ over the
//! Unix socket, and exits. Operator-facing verbs (`plan submit`,
//! `plan decide`, …) arrive in slices C–F as the wire types they
//! depend on get wired up on the writ side.
//!
//! Connecting (without sending a request) is the smallest exercise
//! that proves the daemon path: bailiff resolves `--socket`/
//! `WRIT_SOCKET`, locates writd, and reaches the listener. A real
//! `RunAgent` round-trip comes in slice B alongside the writ-side
//! signing path.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::Parser;
use writ::server::default_socket_path;

#[derive(Parser)]
#[command(
    name = "bailiff",
    about = "bailiff workflow orchestrator (skeleton — no commands yet)"
)]
struct Args {
    /// Path to the writ broker Unix socket. Falls back to
    /// `default_socket_path()` if neither the flag nor `WRIT_SOCKET`
    /// is set, matching the writ CLI's resolution order.
    #[arg(long, env = "WRIT_SOCKET")]
    socket: Option<PathBuf>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let args = Args::parse();
    let socket_path = args.socket.unwrap_or_else(default_socket_path);

    // Open and drop. Sending nothing is intentional: writ's read loop
    // will see EOF and tidy up. Slice B replaces this with the first
    // real `RunAgent` round-trip; until then the connect succeeding
    // is the only signal bailiff needs to confirm it can find writ.
    let _stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("cannot connect to {}: {e}", socket_path.display()))?;
    println!("bailiff: connected to writ at {}", socket_path.display());
    Ok(())
}
