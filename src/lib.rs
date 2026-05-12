//! writ: a local daemon that mints short-lived, per-request-scoped
//! credentials for agents and records every grant in an append-only
//! audit log.
//!
//! See `docs/design/broker.md` for the architecture overview.

pub mod agent_plan;
pub mod agent_run;
#[cfg(feature = "host")]
pub mod agent_vm_daemon;
#[cfg(feature = "host")]
pub mod agent_vm_firewall;
#[cfg(feature = "host")]
pub mod agent_vm_lifecycle;
#[cfg(feature = "host")]
pub mod audit;
pub(crate) mod bearer;
#[cfg(feature = "host")]
pub(crate) mod clean_git;
#[cfg(feature = "host")]
pub mod config;
pub mod core;
#[cfg(feature = "host")]
pub mod git_push_replay;
#[cfg(feature = "host")]
pub mod git_push_staging;
#[cfg(feature = "host")]
pub mod github;
#[cfg(feature = "host")]
pub mod nix_cache;
#[cfg(feature = "host")]
pub mod openai_chatgpt_auth;
#[cfg(feature = "host")]
pub mod policy;
pub mod process_spawn;
#[cfg(feature = "host")]
pub mod protocol;
#[cfg(feature = "host")]
pub mod secret;
#[cfg(feature = "host")]
pub mod server;
pub mod telemetry;
#[cfg(feature = "vm-client")]
pub mod vm_client;
#[cfg(feature = "vm-client")]
pub mod vm_git;
#[cfg(feature = "host")]
pub mod vm_git_bundle;
#[cfg(feature = "host")]
pub mod vm_http;
