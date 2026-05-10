//! Operator-facing structured logging.
//!
//! Installs a JSON [`tracing`] subscriber that writes line-delimited
//! events to stderr. The audit log remains the system of record for
//! grants and proxy outcomes; tracing covers the operational dimension
//! where today the codebase has only ad-hoc `eprintln!`.
//!
//! Filter precedence: the `RUST_LOG` environment variable if set,
//! otherwise the `default_filter` passed to [`init`].

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Failure to install the global tracing subscriber.
#[derive(Debug, thiserror::Error)]
#[error("telemetry init failed: {0}")]
pub struct TelemetryInitError(String);

/// Install a JSON tracing subscriber writing to stderr.
///
/// `default_filter` is used when `RUST_LOG` is unset or unparseable
/// (e.g. `"info"` for the daemon, `"warn"` for short-lived CLIs).
pub fn init(default_filter: &str) -> Result<(), TelemetryInitError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .map_err(|e| TelemetryInitError(format!("invalid filter directive: {e}")))?;
    let layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr);
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
        .map_err(|e| TelemetryInitError(format!("subscriber already installed: {e}")))?;
    Ok(())
}
