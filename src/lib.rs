//! writ: a local daemon that mints short-lived, per-request-scoped
//! credentials for agents and records every grant in an append-only
//! audit log.
//!
//! See `docs/design/architecture.md` for the current-state architecture map
//! (one section per subsystem, with pointers back into these modules).

pub use writ_agent_run as agent_run;
#[cfg(feature = "host")]
pub mod agent_run_envelope;
#[cfg(feature = "host")]
pub mod agent_vm_daemon;
#[cfg(feature = "host")]
pub mod agent_vm_firewall;
#[cfg(feature = "host")]
pub mod agent_vm_lifecycle;
#[cfg(feature = "host")]
pub use writ_audit as audit;
#[cfg(feature = "host")]
pub(crate) use writ_core::bearer;
#[cfg(feature = "host")]
pub mod boot_reconcile;
#[cfg(feature = "host")]
pub mod broker_entrypoint;
#[cfg(feature = "host")]
pub mod broker_log_forwarder;
#[cfg(feature = "host")]
pub mod broker_protocol;
#[cfg(feature = "host")]
pub mod broker_session;
#[cfg(feature = "host")]
pub mod broker_vm;
#[cfg(feature = "host")]
pub mod broker_vm_runner;
#[cfg(feature = "host")]
pub(crate) mod clean_git;
#[cfg(feature = "host")]
pub mod cli;
#[cfg(feature = "host")]
pub mod config;
pub use writ_core::core;
#[cfg(feature = "host")]
pub(crate) mod crash_point;
#[cfg(all(test, feature = "host"))]
pub(crate) mod fake_github;
#[cfg(all(test, feature = "host"))]
pub(crate) mod fake_origin;
#[cfg(all(test, feature = "host"))]
pub(crate) mod flake_fixtures;
#[cfg(feature = "host")]
pub mod flake_lock;
#[cfg(feature = "host")]
pub mod flake_materialize;
#[cfg(feature = "host")]
pub mod flake_provision;
#[cfg(feature = "host")]
pub mod flake_provision_from_mirror;
#[cfg(feature = "host")]
pub mod git_commit_sign;
#[cfg(feature = "host")]
pub mod git_push_approve;
#[cfg(feature = "host")]
pub(crate) mod git_push_object_parse;
#[cfg(feature = "host")]
pub mod git_push_objects_cat_file;
#[cfg(feature = "host")]
pub mod git_push_promote;
#[cfg(feature = "host")]
pub mod git_push_staging;
#[cfg(feature = "host")]
pub mod git_push_trailers;
#[cfg(feature = "host")]
pub mod git_push_walker;
#[cfg(feature = "host")]
pub mod github;
#[cfg(feature = "host")]
pub mod github_git_db;
#[cfg(feature = "host")]
pub mod nix_binary_cache;
#[cfg(feature = "host")]
pub mod notes_repo;
#[cfg(feature = "host")]
pub mod openai_chatgpt_auth;
#[cfg(feature = "host")]
pub mod policy;
pub use writ_core::process_spawn;
#[cfg(feature = "host")]
pub(crate) mod process_supervisor;
#[cfg(feature = "host")]
pub mod protocol;
#[cfg(feature = "host")]
pub mod run_envelope;
#[cfg(feature = "host")]
pub mod run_provenance;
#[cfg(feature = "host")]
pub mod run_verify;
#[cfg(feature = "host")]
pub mod secret;
#[cfg(feature = "host")]
pub mod server;
#[cfg(feature = "host")]
pub mod signing;
pub use writ_core::telemetry;
#[cfg(feature = "host")]
pub mod ui_http;
#[cfg(feature = "vm-client")]
pub use writ_vm_client as vm_client;
// The shared VM-git wire types are needed by both the host (git pipeline, agent
// VM) and the guest client, so the re-export is available under either feature.
#[cfg(any(feature = "host", feature = "vm-client"))]
pub use writ_vm_git as vm_git;
#[cfg(feature = "host")]
pub mod vm_git_bundle;
#[cfg(feature = "host")]
pub mod vm_git_mirror_cache;
#[cfg(feature = "host")]
pub mod vm_http;
#[cfg(feature = "host")]
pub mod writ_client;
