//! The one definition of "SIGKILL a process group we created".
//!
//! It lives here, rather than beside its first caller, because there are now
//! two of them in different crates: the root crate's `process_supervisor`,
//! which runs short helper commands to a deadline, and `writ-agent-run`, which
//! runs agents and cannot depend on the root crate. Two copies of this would be
//! two places to get the benign-errno argument wrong, and that argument took
//! three rounds of review to state correctly the first time.
//!
//! **The precondition every caller owes.** A group kill is only safe while the
//! caller still holds the group's **leader unreaped**. The leader's pid is then
//! still claimed, so the pgid — which equals it — cannot have been recycled
//! onto a group we do not own. Order every use observe-then-kill-then-reap.

/// Narrow a pid to the signed type `killpg` takes.
///
/// `None` for a pid that does not fit, which cannot happen for a child of this
/// process on any real platform but is not worth an `as` cast: the value would
/// wrap to something negative, and a negative pgid is a different request
/// entirely.
#[cfg(unix)]
pub fn process_group_id(pid: u32) -> Option<libc::pid_t> {
    pid.try_into().ok()
}

/// Has `pid` exited, without consuming its exit status?
///
/// The observe half of observe-then-kill-then-reap. A plain `wait` would reap,
/// freeing the pid — and with it the pgid — so a group kill after it could land
/// on a group some other process now leads. `WNOWAIT` answers the same question
/// and leaves the zombie in place, which is what keeps the pgid ours until the
/// caller is finished with the group.
#[cfg(unix)]
pub fn pid_has_exited_without_reaping(pid: libc::pid_t) -> std::io::Result<bool> {
    let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: `waitid` writes only through the out-pointer, which points at a
    // zeroed `siginfo_t` that outlives the call. `WNOWAIT` leaves the child
    // unreaped; `WNOHANG` makes the call non-blocking.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            status.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `waitid` returned success, so it initialised the struct. The
    // zeroing above is what makes `si_pid == 0` readable as "no state change",
    // which is how `WNOHANG` reports "not yet".
    let status = unsafe { status.assume_init() };
    let observed_pid = unsafe { status.si_pid() };
    Ok(observed_pid != 0)
}

/// SIGKILL a process group this process created, tolerating exactly the two
/// benign outcomes and no others.
///
/// Both benign cases are easy to get wrong in opposite directions — swallow too
/// much and a real permission failure becomes invisible; swallow too little and
/// normal shutdown reports a spurious error:
///
/// * `ESRCH` — the group is already gone. Always fine.
/// * `EPERM` — macOS reports this, rather than `ESRCH`, for a group with no
///   signalable member left. Tolerated when `empty_group_is_benign`.
///
/// The condition that makes `EPERM` safe to accept is the module-level
/// precondition: the caller still holds the group's **leader unreaped**. The
/// leader's pid is then still claimed, so the pgid — which equals it — cannot
/// have been recycled onto a group we do not own; and since the group was
/// created with `process_group(0)`, the only way we can fail to signal our own
/// group is that every member has already exited.
///
/// This was previously gated on having *observed* the leader exit, which is a
/// strictly narrower condition than the argument requires, and it left the
/// timeout arms exposed: a child that exits between the deadline and the kill —
/// or that takes `SIGPIPE` when a capture pipe closes — empties the group, and
/// a plain timeout surfaced as a kill failure. Reproduced at roughly 1 run in
/// 24 before the fix. Two earlier rounds of review each fixed one arm of this;
/// naming the real precondition is what stops it recurring in a third.
#[cfg(unix)]
pub fn kill_process_group(pgid: libc::pid_t, empty_group_is_benign: bool) -> std::io::Result<()> {
    // The child was spawned with process_group(0), making its pid the process
    // group id inherited by any ordinary helpers it starts.
    //
    // SAFETY: `killpg` takes no pointers and has no memory effects.
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    match source.raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        Some(libc::EPERM) if empty_group_is_benign => Ok(()),
        _ => Err(source),
    }
}
