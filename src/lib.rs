//! writ: a local daemon that mints short-lived, per-request-scoped
//! credentials for agents and records every grant in an append-only
//! audit log.
//!
//! See `docs/design/broker.md` for the architecture overview.

pub mod audit;
pub mod core;
pub mod github;
pub mod policy;
pub mod secret;
