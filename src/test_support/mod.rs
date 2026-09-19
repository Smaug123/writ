//! Test scaffolding shared by this crate's tests and, through the
//! `test-support` feature, by downstream crates' tests (bailiff).
//!
//! Nothing here is compiled into a production build. Each item exists because
//! the same helper had been re-typed in several test modules, and copies drift:
//! one PATH lookup accepted non-executable files, one `create_dir` was
//! recursive and another was not. One definition, one behaviour.

mod broker;
mod fixtures;
mod path;
mod secret;

pub use broker::{
    GITHUB_APP_SECRET, SpawnedBroker, broker_state, cat_run_agent_spawn, claude_broker_state,
    github_app,
};
pub use fixtures::*;
pub use path::{
    find_in_path, required_tool, required_tool_any, shell_quote_path, shell_single_quote,
    write_executable_script,
};
pub use secret::InMemorySecretStore;
