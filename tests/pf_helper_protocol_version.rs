//! The built `writ-agent-vm-pf-helper` answers `protocol-version` on stdout
//! with exactly what the host-side parser accepts: this is the seam the
//! daemon's locked-profile admission will read, so it is exercised end to end
//! through the real binary (`main`, `println!`, telemetry init and all), not
//! only through the dispatch function the bin's unit tests call.

use std::process::{Command, Stdio};

use writ::agent_vm_pf_helper_protocol::{PF_HELPER_PROTOCOL_MAX_BYTES, PfHelperProtocolDoc};

const HELPER: &str = env!("CARGO_BIN_EXE_writ-agent-vm-pf-helper");

#[test]
fn the_real_helper_prints_one_parseable_line() {
    let mut command = Command::new(HELPER);
    command
        .arg("protocol-version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Through the workspace's retrying primitive, as the spawn-hygiene guard
    // requires.
    let output = writ::process_spawn::output(&mut command).expect("spawn the helper");

    let stdout = String::from_utf8(output.stdout).expect("helper stdout is UTF-8");
    assert!(
        output.status.success(),
        "helper failed: {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.len() <= PF_HELPER_PROTOCOL_MAX_BYTES);
    assert_eq!(
        stdout,
        format!("{}\n", PfHelperProtocolDoc::current().render())
    );
    assert_eq!(
        PfHelperProtocolDoc::parse(&stdout),
        Ok(PfHelperProtocolDoc::current())
    );
}
