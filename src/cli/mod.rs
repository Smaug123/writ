//! CLI helpers extracted from the `writ` binary so the binary stays
//! focused on clap-derive types and dispatch. Pure helpers and output
//! writers live here so they can be unit-tested without the binary's
//! socket/argv machinery in the way.

pub mod output;
