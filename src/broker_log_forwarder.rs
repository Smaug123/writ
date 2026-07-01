//! Host-side tail of the broker VM's mirrored log file.
//!
//! The broker (`writd broker`) runs inside a guest whose stderr is only
//! reachable via `container logs`; to make its diagnostics visible to the host
//! daemon the broker mirrors its JSON tracing to a file on the shared session
//! mount (see [`crate::telemetry::init_with_file`]). This module tails that
//! file from the host and re-emits each line into the daemon's own tracing, so
//! a broker-side failure (e.g. a rejected nix-cache narinfo) surfaces in the
//! logs the operator is already watching — no `container logs` required.
//!
//! The forwarder starts *before* the broker's ready-wait (so a readiness
//! timeout still forwards the broker's egress-probe warnings) and is drained
//! one final time on stop (so the lines written just before teardown, which are
//! usually the failure itself, are not lost).
//!
//! Correctness rests on the file being **append-only and monotonic** (the
//! broker truncates on open, then only appends up to a byte cap): the tailer
//! keeps a byte offset that only advances, and reassembles complete lines
//! across arbitrary read boundaries.

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::core::SessionId;

/// Longest broker line re-emitted verbatim into a host event; longer lines are
/// truncated so a single pathological line can't bloat a host log record.
const MAX_FORWARDED_LINE_BYTES: usize = 16 * 1024;
/// Appended to a forwarded line that was truncated at [`MAX_FORWARDED_LINE_BYTES`].
const TRUNCATION_MARKER: &str = "…[writ: broker log line truncated]";
/// Bytes read from the broker log per read syscall batch. The log path is on a
/// mount the broker VM can write, so this bounds host memory even if a
/// misbehaving/compromised broker writes far past its own [`crate::telemetry`]
/// cap; a backlog is drained across several bounded reads.
const MAX_READ_CHUNK_BYTES: u64 = 1024 * 1024;

/// A running tail of one broker VM's log file. Drop-safe: dropping aborts the
/// task without a final drain, so prefer [`Self::drain_and_stop`] on teardown.
pub struct BrokerLogForwarder {
    stop: Arc<Notify>,
    handle: JoinHandle<()>,
}

impl BrokerLogForwarder {
    /// Start tailing `path` and forwarding lines under `session_id`, polling
    /// every `poll_interval`. The file need not exist yet.
    pub fn spawn(path: PathBuf, session_id: SessionId, poll_interval: Duration) -> Self {
        let stop = Arc::new(Notify::new());
        let stop_task = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            let mut offset: u64 = 0;
            let mut reassembler = LineReassembler::default();
            loop {
                drain_into(&path, &mut offset, &mut reassembler, |line| {
                    forward_line(session_id, line)
                });
                tokio::select! {
                    _ = stop_task.notified() => break,
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            }
            // Final drain: capture anything written between the last poll and
            // stop (typically the failure that triggered teardown).
            drain_into(&path, &mut offset, &mut reassembler, |line| {
                forward_line(session_id, line)
            });
        });
        Self { stop, handle }
    }

    /// Signal the tail to stop, let it do one last drain, and await it. Used on
    /// both the success-teardown and failure paths.
    pub async fn drain_and_stop(self) {
        self.stop.notify_one();
        let _ = self.handle.await;
    }
}

/// Open the broker log for reading, refusing to follow symlinks or read
/// anything but a regular file.
///
/// The log path lives on a mount the broker VM can write, so it is untrusted
/// input (see [`crate::broker_vm::BROKER_VM_SESSION_DIR`], mounted read-write).
/// `O_NOFOLLOW` fails the open if the final component is a symlink (so the host
/// can't be steered into reading a host file), and `O_NONBLOCK` keeps the open
/// from blocking on a FIFO; the `is_file` check then rejects FIFOs/devices. A
/// missing file (the broker may not have created it yet) is a plain `None`.
fn open_regular_no_follow(path: &Path) -> Option<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.file_type().is_file() {
        return None;
    }
    Some(file)
}

/// Read from `offset` to the current end of `path` and emit every complete line
/// the new bytes complete, advancing `offset`. A missing/unreadable/non-regular
/// path emits nothing. Reads are chunked at [`MAX_READ_CHUNK_BYTES`] and the
/// full backlog is drained (looping) so a bounded per-read never loses the tail,
/// while host memory stays bounded regardless of the file's size.
fn drain_into(
    path: &Path,
    offset: &mut u64,
    reassembler: &mut LineReassembler,
    mut emit: impl FnMut(&[u8]),
) {
    let mut file = match open_regular_no_follow(path) {
        Some(file) => file,
        None => return,
    };
    // If the file shrank below our offset it was truncated/rewritten — e.g. a
    // reused session staging dir whose stale log the broker truncated on open.
    // Restart from the top and drop the now-meaningless partial so fresh content
    // is not skipped.
    let shrank = file.metadata().map(|m| m.len() < *offset).unwrap_or(false);
    if shrank {
        *offset = 0;
        reassembler.partial.clear();
    }
    loop {
        if file.seek(SeekFrom::Start(*offset)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        let read = (&mut file).take(MAX_READ_CHUNK_BYTES).read_to_end(&mut buf);
        let n = match read {
            Ok(n) => n,
            Err(_) => return,
        };
        if n == 0 {
            return;
        }
        *offset += n as u64;
        for line in reassembler.push(&buf) {
            emit(&line);
        }
        // A short read means we reached EOF; a full chunk means there may be
        // more backlog, so keep draining.
        if (n as u64) < MAX_READ_CHUNK_BYTES {
            return;
        }
    }
}

/// Re-emit one broker line into the host's tracing, preserving its level and
/// tagging it so it is distinguishable from (and greppable against) native host
/// events.
fn forward_line(session_id: SessionId, raw: &[u8]) {
    let full = String::from_utf8_lossy(raw);
    let level = classify_broker_line(&full);
    let line = truncate_for_forward(&full);
    match level {
        tracing::Level::ERROR => {
            tracing::error!(source = "broker-vm", %session_id, broker = %line)
        }
        tracing::Level::WARN => {
            tracing::warn!(source = "broker-vm", %session_id, broker = %line)
        }
        tracing::Level::DEBUG => {
            tracing::debug!(source = "broker-vm", %session_id, broker = %line)
        }
        tracing::Level::TRACE => {
            tracing::trace!(source = "broker-vm", %session_id, broker = %line)
        }
        tracing::Level::INFO => {
            tracing::info!(source = "broker-vm", %session_id, broker = %line)
        }
    }
}

/// Best-effort recover the broker event's level from its JSON `level` field so
/// broker `warn`/`error`s surface at the same level on the host. Anything
/// unparseable (a torn or non-JSON line) forwards at INFO.
fn classify_broker_line(line: &str) -> tracing::Level {
    match serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .as_ref()
        .and_then(|value| value.get("level"))
        .and_then(|level| level.as_str())
    {
        Some("ERROR") => tracing::Level::ERROR,
        Some("WARN") => tracing::Level::WARN,
        Some("DEBUG") => tracing::Level::DEBUG,
        Some("TRACE") => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

/// Cap a forwarded line at [`MAX_FORWARDED_LINE_BYTES`], truncating on a UTF-8
/// char boundary and appending a marker.
fn truncate_for_forward(line: &str) -> String {
    if line.len() <= MAX_FORWARDED_LINE_BYTES {
        return line.to_string();
    }
    let mut end = MAX_FORWARDED_LINE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARKER}", &line[..end])
}

/// Reassembles a byte stream delivered in arbitrary chunks into complete,
/// newline-terminated lines. Bytes after the final `\n` are held as a partial
/// until their newline arrives. Pure; the unit of correctness the tail loop is
/// built on.
#[derive(Default)]
struct LineReassembler {
    partial: Vec<u8>,
}

impl LineReassembler {
    /// Feed the next chunk, returning every complete line it completes (each
    /// without its trailing `\n`).
    fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.partial.extend_from_slice(chunk);
        let mut lines = Vec::new();
        let mut start = 0;
        for (i, &byte) in self.partial.iter().enumerate() {
            if byte == b'\n' {
                lines.push(self.partial[start..i].to_vec());
                start = i + 1;
            }
        }
        self.partial.drain(..start);
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn classify_maps_levels_and_defaults_to_info() {
        assert_eq!(
            classify_broker_line(r#"{"level":"WARN","fields":{"message":"x"}}"#),
            tracing::Level::WARN
        );
        assert_eq!(
            classify_broker_line(r#"{"level":"ERROR"}"#),
            tracing::Level::ERROR
        );
        assert_eq!(
            classify_broker_line(r#"{"level":"INFO"}"#),
            tracing::Level::INFO
        );
        // Torn / non-JSON / missing level all fall back to INFO.
        assert_eq!(
            classify_broker_line("not json at all"),
            tracing::Level::INFO
        );
        assert_eq!(
            classify_broker_line(r#"{"msg":"no level"}"#),
            tracing::Level::INFO
        );
    }

    #[test]
    fn truncate_leaves_short_lines_and_caps_long_ones() {
        assert_eq!(truncate_for_forward("short"), "short");
        let long = "é".repeat(MAX_FORWARDED_LINE_BYTES); // 2 bytes each
        let out = truncate_for_forward(&long);
        assert!(out.ends_with(TRUNCATION_MARKER));
        assert!(out.len() <= MAX_FORWARDED_LINE_BYTES + TRUNCATION_MARKER.len());
        // Truncation landed on a char boundary (no panic building `out`).
        assert!(out[..out.len() - TRUNCATION_MARKER.len()].chars().count() > 0);
    }

    /// Drain `path` and collect the emitted lines (tests exercise the pure
    /// read/reassemble logic without a tracing subscriber).
    fn collect(path: &Path, offset: &mut u64, reasm: &mut LineReassembler) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        drain_into(path, offset, reasm, |line| got.push(line.to_vec()));
        got
    }

    #[test]
    fn drain_advances_offset_across_partial_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let mut offset = 0u64;
        let mut reasm = LineReassembler::default();

        // Missing file yields nothing.
        assert!(collect(&path, &mut offset, &mut reasm).is_empty());

        std::fs::write(&path, b"a\nb\n").unwrap();
        assert_eq!(
            collect(&path, &mut offset, &mut reasm),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(offset, 4);

        // A line split across two reads: the partial is held until its newline.
        std::fs::write(&path, b"a\nb\nc").unwrap();
        assert!(collect(&path, &mut offset, &mut reasm).is_empty());
        assert_eq!(offset, 5);
        std::fs::write(&path, b"a\nb\nc\nd\n").unwrap();
        assert_eq!(
            collect(&path, &mut offset, &mut reasm),
            vec![b"c".to_vec(), b"d".to_vec()]
        );
        assert_eq!(offset, 8);
    }

    #[test]
    fn drain_restarts_after_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let mut offset = 0u64;
        let mut reasm = LineReassembler::default();

        // A stale log (with a dangling partial) from a prior attempt.
        std::fs::write(&path, b"old1\nold2\npart").unwrap();
        assert_eq!(
            collect(&path, &mut offset, &mut reasm),
            vec![b"old1".to_vec(), b"old2".to_vec()]
        );
        assert_eq!(offset, 14);

        // The broker truncates on open and writes fresh content, shrinking the
        // file below the offset: the tail restarts from 0 (and the stale partial
        // does not prepend to the new content).
        std::fs::write(&path, b"new\n").unwrap();
        assert_eq!(
            collect(&path, &mut offset, &mut reasm),
            vec![b"new".to_vec()]
        );
        assert_eq!(offset, 4);
    }

    #[test]
    fn drain_refuses_to_follow_a_symlink_to_a_host_file() {
        // The broker-writable log path must never let the host read an arbitrary
        // file it points a symlink at.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("host-secret");
        std::fs::write(&victim, b"top-secret\n").unwrap();
        let log = dir.path().join("broker.log");
        std::os::unix::fs::symlink(&victim, &log).unwrap();

        let mut offset = 0u64;
        let mut reasm = LineReassembler::default();
        assert!(
            collect(&log, &mut offset, &mut reasm).is_empty(),
            "must not follow a symlink to a host file"
        );
        assert_eq!(offset, 0);

        // A fresh regular file at the same path is read normally.
        std::fs::remove_file(&log).unwrap();
        std::fs::write(&log, b"real\n").unwrap();
        assert_eq!(
            collect(&log, &mut offset, &mut reasm),
            vec![b"real".to_vec()]
        );
    }

    #[test]
    fn drain_reads_a_backlog_larger_than_one_chunk() {
        // A backlog exceeding MAX_READ_CHUNK_BYTES is drained fully (looping)
        // without loading it all at once.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let line_count = 4;
        let filler = "x".repeat(MAX_READ_CHUNK_BYTES as usize / 2);
        let content: String = (0..line_count).map(|_| format!("{filler}\n")).collect();
        std::fs::write(&path, content.as_bytes()).unwrap();

        let mut offset = 0u64;
        let mut reasm = LineReassembler::default();
        let got = collect(&path, &mut offset, &mut reasm);
        assert_eq!(got.len(), line_count);
        assert_eq!(offset, content.len() as u64);
    }

    #[tokio::test]
    async fn spawn_and_drain_stop_terminates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        std::fs::write(&path, b"{\"level\":\"WARN\"}\n").unwrap();
        let forwarder = BrokerLogForwarder::spawn(path, SessionId::new(), Duration::from_millis(5));
        // drain_and_stop must return promptly (final drain then join).
        tokio::time::timeout(Duration::from_secs(5), forwarder.drain_and_stop())
            .await
            .expect("forwarder stopped");
    }

    proptest! {
        /// Reassembly is independent of chunk boundaries: for any split of the
        /// content, the emitted lines equal the content split on `\n` (minus the
        /// unterminated trailing partial), and the held partial equals the tail.
        #[test]
        fn reassembler_matches_split_oracle(
            content in proptest::collection::vec(any::<u8>(), 0..300),
            chunk_sizes in proptest::collection::vec(1usize..16, 1..40),
        ) {
            let mut reasm = LineReassembler::default();
            let mut got: Vec<Vec<u8>> = Vec::new();
            let mut i = 0;
            let mut sizes = chunk_sizes.iter().cycle();
            while i < content.len() {
                let n = (*sizes.next().unwrap()).min(content.len() - i);
                got.extend(reasm.push(&content[i..i + n]));
                i += n;
            }

            let mut oracle: Vec<Vec<u8>> = Vec::new();
            let mut start = 0;
            for (idx, &b) in content.iter().enumerate() {
                if b == b'\n' {
                    oracle.push(content[start..idx].to_vec());
                    start = idx + 1;
                }
            }
            prop_assert_eq!(&got, &oracle);
            prop_assert_eq!(&reasm.partial, &content[start..].to_vec());
        }
    }
}
