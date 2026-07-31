//! `writ-core`: the dependency-free foundation of writ.
//!
//! Pure data types (`core`), shared low-level helpers (`bearer`, `git_env`,
//! `process_spawn`), and operator telemetry (`telemetry`). These modules
//! have no dependencies on the rest of writ, so they live in their own
//! crate: editing the application layers no longer recompiles them, and
//! they build in parallel with the bulk of the dependency tree.
//!
//! Being the crate everything else depends on also makes this the right home
//! for anything that must have exactly one definition across the workspace —
//! `git_env`'s hardened Git recipe and `process_spawn`'s transient-refusal
//! classification are both here because a copy in a crate the others cannot
//! reach is a copy that will drift.
//!
//! The parent `writ` crate re-exports these modules, so `crate::core`,
//! `crate::telemetry`, etc. continue to resolve unchanged.

pub mod bearer;
pub mod byte_size;
pub mod core;
pub mod git_env;
pub mod process_group;
pub mod process_spawn;
pub mod telemetry;
