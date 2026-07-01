//! Operator-facing structured logging.
//!
//! Installs a JSON `tracing` subscriber that writes line-delimited
//! events to stderr. The audit log remains the system of record for
//! grants and proxy outcomes; tracing covers the operational dimension
//! where today the codebase has only ad-hoc `eprintln!`.
//!
//! Filter precedence: the `RUST_LOG` environment variable if set,
//! otherwise the `default_filter` passed to [`init`].
//!
//! The broker VM runs `writd broker` inside a guest whose stderr is only
//! reachable via `container logs`. To surface its diagnostics on the host,
//! [`init_with_file`] adds a *second* JSON sink writing to a file on the
//! shared session mount; the host daemon tails that file (see the host-side
//! `broker_log_forwarder`) and re-emits each line into its own logs.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Failure to install the global tracing subscriber.
#[derive(Debug, thiserror::Error)]
#[error("telemetry init failed: {0}")]
pub struct TelemetryInitError(String);

/// Default byte cap for the broker's mirrored log file. An anti-runaway bound
/// hit only pathologically; append-only + hard cap keeps the file **monotonic**
/// so the host tailer's byte offset never has to account for truncation.
pub const BROKER_LOG_FILE_CAP_BYTES: u64 = 8 * 1024 * 1024;

/// The single line appended (once) when [`BoundedFileWriter`] first drops output
/// at the cap. Leading `\n` guarantees it lands on its own line even if the
/// event that crossed the cap was written without a trailing newline.
const CAP_NOTICE: &str =
    "\n{\"writ_broker_log\":\"log file cap reached; remaining logs only via `container logs`\"}\n";

/// An append-only [`Write`] that stops accepting event bytes once a byte cap is
/// reached, appending a one-time `CAP_NOTICE` line the first time it drops.
///
/// Whole buffers are written or dropped, never split, so every JSON line stays
/// intact; the overshoot past the cap is bounded by a single write. The file is
/// truncated on open (the broker's session mount is fresh per session), so the
/// host tailer can start at offset 0.
pub struct BoundedFileWriter {
    file: File,
    written: u64,
    cap: u64,
    notice_written: bool,
}

impl BoundedFileWriter {
    /// Create (truncating) the file at `path`, capped at `cap` bytes.
    pub fn create(path: &Path, cap: u64) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file,
            written: 0,
            cap,
            notice_written: false,
        })
    }

    fn write_notice_once(&mut self) -> io::Result<()> {
        if !self.notice_written {
            self.notice_written = true;
            self.file.write_all(CAP_NOTICE.as_bytes())?;
        }
        Ok(())
    }
}

impl Write for BoundedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written >= self.cap {
            // Cap reached: emit the notice once, then swallow the rest (report
            // the bytes as consumed so the caller doesn't spin retrying).
            self.write_notice_once()?;
            return Ok(buf.len());
        }
        self.file.write_all(buf)?;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Install a JSON tracing subscriber writing to stderr.
///
/// `default_filter` is used when `RUST_LOG` is unset or unparseable
/// (e.g. `"info"` for the daemon, `"warn"` for short-lived CLIs).
pub fn init(default_filter: &str) -> Result<(), TelemetryInitError> {
    init_with_file(default_filter, None)
}

/// Like [`init`], but additionally mirrors events (as JSON) to `log_file` when
/// given. Used by `writd broker` to publish its logs onto the shared session
/// mount for the host to tail. The file sink is byte-capped
/// ([`BROKER_LOG_FILE_CAP_BYTES`]) and wrapped in a `Mutex` so each event's
/// bytes are written without interleaving across threads.
pub fn init_with_file(
    default_filter: &str,
    log_file: Option<&Path>,
) -> Result<(), TelemetryInitError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .map_err(|e| TelemetryInitError(format!("invalid filter directive: {e}")))?;
    let stderr_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer);
    let already = |e: tracing_subscriber::util::TryInitError| {
        TelemetryInitError(format!("subscriber already installed: {e}"))
    };
    match log_file {
        None => registry.try_init().map_err(already),
        Some(path) => {
            let writer =
                BoundedFileWriter::create(path, BROKER_LOG_FILE_CAP_BYTES).map_err(|e| {
                    TelemetryInitError(format!(
                        "cannot open broker log file {}: {e}",
                        path.display()
                    ))
                })?;
            let file_layer = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(Mutex::new(writer));
            registry.with(file_layer).try_init().map_err(already)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Reference model of the soft-cap: accept whole buffers until the running
    /// total first reaches `cap`, then drop the rest and append the notice.
    fn expected_file(chunks: &[Vec<u8>], cap: u64) -> Vec<u8> {
        let mut written: u64 = 0;
        let mut accepted: Vec<u8> = Vec::new();
        let mut dropped = false;
        for chunk in chunks {
            if written >= cap {
                dropped = true;
            } else {
                accepted.extend_from_slice(chunk);
                written += chunk.len() as u64;
            }
        }
        if dropped {
            accepted.extend_from_slice(CAP_NOTICE.as_bytes());
        }
        accepted
    }

    proptest! {
        /// The on-disk bytes exactly match the reference soft-cap model, and the
        /// file is bounded by cap + one overshooting write + the notice.
        #[test]
        fn bounded_writer_matches_reference_and_is_bounded(
            chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..64),
                0..40,
            ),
            cap in 1u64..1024,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("broker.log");
            let mut writer = BoundedFileWriter::create(&path, cap).unwrap();
            let max_chunk = chunks.iter().map(|c| c.len() as u64).max().unwrap_or(0);
            for chunk in &chunks {
                // `Write::write` reports the whole buffer consumed by contract.
                let n = writer.write(chunk).unwrap();
                prop_assert_eq!(n, chunk.len());
            }
            writer.flush().unwrap();
            drop(writer);

            let on_disk = std::fs::read(&path).unwrap();
            prop_assert_eq!(&on_disk, &expected_file(&chunks, cap));
            prop_assert!(
                on_disk.len() as u64 <= cap + max_chunk + CAP_NOTICE.len() as u64,
                "file {} exceeds cap {} + overshoot {} + notice {}",
                on_disk.len(), cap, max_chunk, CAP_NOTICE.len(),
            );
        }
    }

    #[test]
    fn no_notice_when_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let mut writer = BoundedFileWriter::create(&path, 1024).unwrap();
        writer.write_all(b"line one\n").unwrap();
        writer.write_all(b"line two\n").unwrap();
        writer.flush().unwrap();
        drop(writer);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, "line one\nline two\n");
        assert!(!on_disk.contains("cap reached"));
    }

    #[test]
    fn notice_appended_once_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let mut writer = BoundedFileWriter::create(&path, 4).unwrap();
        writer.write_all(b"aaaa").unwrap(); // fills cap exactly
        writer.write_all(b"bbbb").unwrap(); // dropped -> notice
        writer.write_all(b"cccc").unwrap(); // dropped -> no second notice
        writer.flush().unwrap();
        drop(writer);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, format!("aaaa{CAP_NOTICE}"));
        assert_eq!(on_disk.matches("cap reached").count(), 1);
    }
}
