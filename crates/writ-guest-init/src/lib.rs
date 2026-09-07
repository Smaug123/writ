//! The agent VM's one-way privilege handoff, as data.
//!
//! Under the `ipv4_only_locked_v1` profile the guest image's PID 1 is a small
//! initializer that starts with a handful of temporary capabilities, disables
//! IPv6, drops every capability irreversibly, becomes an unprivileged fixed
//! identity, and only then waits for the host's release signal. This crate is
//! the pure description of that sequence and of what the host may expect once
//! it has happened:
//!
//! - [`capability_argv`]: the exact `container run` capability arguments the
//!   initializer is launched with, and a parser that accepts nothing else.
//! - [`handoff`]: the ordered steps of the handoff, and a reference model of
//!   the Linux privilege rules those steps run under, so that an order which
//!   could not complete (dropping `CAP_SETUID` before `setresuid`, say) is a
//!   test failure here rather than an `EPERM` inside a VM.
//! - [`proc_status`]: the shape of `/proc/<pid>/status` a locked process
//!   must have, parsed and checked, at each of the two moments it is read:
//!   before release, while PID 1 is parked in `sigwait` with `SIGUSR1`
//!   blocked, and after `exec`, when the workload must have it unblocked.
//!   The host's release gate refuses anything that is not the former.
//!
//! Nothing here performs an effect. The interpreter, a Linux-only binary that
//! runs as PID 1, is a separate stage of the plan in
//! `docs/plans/2026-09-01-ipv4-only-locked-v1.md`.

pub mod capability_argv;
pub mod handoff;
pub mod proc_status;

/// The fixed unprivileged identity every locked workload runs as.
///
/// Not a knob: the official image is built around it, and the host's
/// pre-release check ([`proc_status::LockedAwaitingRelease`]) refuses any
/// other.
pub const LOCKED_UID: u32 = 1000;
/// See [`LOCKED_UID`].
pub const LOCKED_GID: u32 = 1000;
