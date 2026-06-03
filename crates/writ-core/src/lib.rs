//! `writ-core`: the dependency-free foundation of writ.
//!
//! Pure data types (`core`), shared low-level helpers (`bearer`,
//! `process_spawn`), and operator telemetry (`telemetry`). These modules
//! have no dependencies on the rest of writ, so they live in their own
//! crate: editing the application layers no longer recompiles them, and
//! they build in parallel with the bulk of the dependency tree.
//!
//! The parent `writ` crate re-exports these modules, so `crate::core`,
//! `crate::telemetry`, etc. continue to resolve unchanged.

pub mod bearer;
pub mod core;
pub mod process_spawn;
pub mod telemetry;
