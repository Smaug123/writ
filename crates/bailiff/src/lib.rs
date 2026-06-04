//! `bailiff`: the plan-workflow product built on top of `writ`.
//!
//! Bailiff drives the per-plan submit → decide → review → implement
//! workflow, recording each step as a signed note in its own bare repo
//! and verifying agent-run envelopes produced by the writ broker. It
//! depends on `writ` for the broker client, run verification, git notes,
//! and shared core types; `writ` has no dependency on bailiff.

pub mod bailiff_decision;
pub mod bailiff_plan_implement;
pub mod bailiff_plan_note;
pub mod bailiff_plan_read;
pub mod bailiff_plan_review;
pub mod bailiff_plan_submit;
pub mod bailiff_plan_view;
pub mod bailiff_plan_write;
pub mod bailiff_repo_guard;
pub mod output;
