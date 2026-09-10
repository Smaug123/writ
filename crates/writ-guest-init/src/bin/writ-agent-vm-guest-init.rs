//! The agent VM initializer: PID 1 under the `ipv4_only_locked_v1` profile.
//!
//! It carries out the one-way privilege handoff described as data in
//! [`writ_guest_init::handoff`], then hands control to the workload. The whole
//! sequence, in order:
//!
//! 1. Block `SIGUSR1` before anything else, so the release wait is armed for
//!    the entire handoff. A signal sent before the wait is entered is held
//!    pending and consumed by it, never lost and never fatal.
//! 2. Enumerate the guest's interfaces and build the canonical handoff plan.
//! 3. Perform each step in order, stopping at the first failure. On failure it
//!    writes one bounded [`writ_guest_init::record::GuestInitRecord::HandoffFailed`]
//!    line and exits without ever starting the workload.
//! 4. On success, write the single
//!    [`writ_guest_init::record::GuestInitRecord::SecurityReady`] line. The
//!    host reads it, reads PID 1's `/proc/1/status` (which must now match
//!    [`writ_guest_init::proc_status::LockedAwaitingRelease`], `SIGUSR1`
//!    blocked), and only then sends `SIGUSR1`.
//! 5. Wait for `SIGUSR1` (via a `signalfd`, which keeps it visibly blocked
//!    while parked), unblock `SIGUSR1` so the workload does not inherit a
//!    blocked signal, and `exec` the workload.
//!
//! Everything effectful lives here; the library it drives performs no effect.
//! The real body is Linux-only. On any other target the binary is a stub that
//! refuses to run, so a host build compiles but cannot mistake it for usable.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "writ-agent-vm-guest-init runs only on Linux, as the agent VM's PID 1; \
         it has no function on this platform"
    );
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use writ_guest_init::handoff::{
        HandoffStep, InterfaceName, Ipv6Sysctl, OwnedDirectory, SysctlScope, handoff_plan,
    };
    use writ_guest_init::proc_status::{LockedAwaitingRelease, ProcStatus};
    use writ_guest_init::record::{BoundedMessage, GuestInitRecord, ISOLATION_ABI_VERSION};
    use writ_guest_init::{LOCKED_GID, LOCKED_UID};

    // prctl operations not all spelled out in libc's older releases; named here
    // from <linux/prctl.h> so the code reads against the kernel's names.
    const PR_CAPBSET_DROP: libc::c_int = 24;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    /// `_LINUX_CAPABILITY_VERSION_3`: the 64-bit, two-block capability ABI.
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// The last OS error, formatted, with a prefix naming the syscall.
    fn os_err(context: &str) -> String {
        format!("{context}: {}", std::io::Error::last_os_error())
    }

    pub fn run() -> ExitCode {
        // The workload to hand off to is this process's argv tail.
        let workload: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        if workload.is_empty() {
            eprintln!(
                "writ-agent-vm-guest-init: no workload command given; usage: \
                 writ-agent-vm-guest-init <program> [args...]"
            );
            return ExitCode::from(2);
        }

        // 1. Arm the release wait before doing anything that could take time.
        if let Err(reason) = arm_sigusr1() {
            // Nothing has changed yet; report and refuse to continue.
            emit(&GuestInitRecord::HandoffFailed {
                step_index: 0,
                message: BoundedMessage::new(&reason),
            });
            return ExitCode::FAILURE;
        }

        // 2. Build the canonical plan for the interfaces that exist now.
        let interfaces = enumerate_interfaces();
        let plan = handoff_plan(&interfaces);

        // 3. Perform each step, stopping at the first failure.
        for (index, step) in plan.iter().enumerate() {
            if let Err(reason) = perform(step) {
                emit(&GuestInitRecord::HandoffFailed {
                    step_index: index,
                    message: BoundedMessage::new(&reason),
                });
                return ExitCode::FAILURE;
            }
        }

        // 4. Announce readiness. The wait is already armed (step 1), so the
        //    host may send SIGUSR1 the instant it reads this line.
        emit(&GuestInitRecord::SecurityReady {
            abi: ISOLATION_ABI_VERSION,
        });

        // 5. Wait for release, unblock the signal, and hand off.
        if let Err(reason) = wait_for_release() {
            // Post-readiness: the record is already out and authority is gone.
            // There is nothing to do but die loudly; the host times out and
            // cleans up. This is not a HandoffFailed record (the handoff
            // succeeded), just a diagnostic.
            eprintln!("writ-agent-vm-guest-init: {reason}");
            return ExitCode::FAILURE;
        }

        let program = &workload[0];
        let error = std::process::Command::new(program)
            .args(&workload[1..])
            .exec();
        // exec only returns on failure.
        eprintln!(
            "writ-agent-vm-guest-init: exec {:?} failed: {error}",
            program
        );
        ExitCode::from(127)
    }

    /// Write a record to stdout as one line and flush, so the host's bounded
    /// log read sees it promptly.
    fn emit(record: &GuestInitRecord) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", record.render());
        let _ = stdout.flush();
    }

    /// The interfaces present, as valid [`InterfaceName`]s, sorted for
    /// determinism. Read from `/proc/net/dev` rather than `/sys/class/net`: it
    /// reflects the reading process's network namespace directly (no sysfs
    /// mount required, and a fresh netns shows only `lo`), which matches how
    /// the per-interface IPv6 sysctls under `/proc/sys/net` are scoped. Its
    /// format is two header lines, then `  <name>: <counters>`. Anything that
    /// is not a valid interface name is skipped rather than failing the
    /// handoff.
    fn enumerate_interfaces() -> Vec<InterfaceName> {
        let text = match std::fs::read_to_string("/proc/net/dev") {
            Ok(text) => text,
            Err(_) => return Vec::new(),
        };
        let mut names: Vec<InterfaceName> = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter_map(|(name, _)| InterfaceName::new(name.trim()).ok())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Map a named directory onto its path. The official image fixes these;
    /// each is overridable by environment variable so a test (or a differently
    /// laid-out image) can point the interpreter at real, chownable paths
    /// without changing what is guarded. The identity handoff itself has no
    /// such knob.
    fn owned_directory_path(dir: OwnedDirectory) -> PathBuf {
        let (var, default) = match dir {
            OwnedDirectory::Runtime => ("WRIT_GUEST_INIT_RUNTIME_DIR", "/run/writ-agent-vm"),
            OwnedDirectory::Home => ("WRIT_GUEST_INIT_HOME_DIR", "/home/writ"),
            OwnedDirectory::Workspace => ("WRIT_GUEST_INIT_WORKSPACE_DIR", "/workspace"),
            OwnedDirectory::NixStore => ("WRIT_GUEST_INIT_NIX_STORE_DIR", "/nix"),
        };
        std::env::var_os(var)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default))
    }

    /// Perform one handoff step. Returns a human reason on failure; the caller
    /// bounds it into the failure record.
    fn perform(step: &HandoffStep) -> Result<(), String> {
        match step {
            HandoffStep::PrepareOwnedDirectory(dir) => prepare_owned_directory(*dir),
            HandoffStep::WriteSysctl { scope, sysctl } => write_sysctl(scope, *sysctl),
            HandoffStep::VerifyNoIpv6 => verify_no_ipv6(),
            HandoffStep::DropBoundingSet => drop_bounding_set(),
            HandoffStep::ClearInheritableAndAmbient => clear_inheritable_and_ambient(),
            HandoffStep::SetNoNewPrivs => set_no_new_privs(),
            HandoffStep::ClearSupplementaryGroups => clear_supplementary_groups(),
            HandoffStep::SetResgid(gid) => set_resgid(*gid),
            HandoffStep::SetResuid(uid) => set_resuid(*uid),
            HandoffStep::VerifyLockedIdentity => verify_locked_identity(),
        }
    }

    fn prepare_owned_directory(dir: OwnedDirectory) -> Result<(), String> {
        let path = owned_directory_path(dir);
        std::fs::create_dir_all(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
        chown_recursive(&path)
    }

    /// `chown -R LOCKED_UID:LOCKED_GID`, not following symlinks. Depth-first so
    /// a failure names the offending path.
    fn chown_recursive(path: &std::path::Path) -> Result<(), String> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(path).map_err(|e| format!("read dir {}: {e}", path.display()))?
            {
                let entry = entry.map_err(|e| format!("read entry in {}: {e}", path.display()))?;
                chown_recursive(&entry.path())?;
            }
        }
        std::os::unix::fs::lchown(path, Some(LOCKED_UID), Some(LOCKED_GID))
            .map_err(|e| format!("chown {}: {e}", path.display()))
    }

    fn write_sysctl(scope: &SysctlScope, sysctl: Ipv6Sysctl) -> Result<(), String> {
        let path = format!(
            "/proc/sys/net/ipv6/conf/{}/{}",
            scope.path_component(),
            sysctl.file_name()
        );
        match std::fs::write(&path, sysctl.locked_value()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !sysctl.must_exist() => {
                // An optional acquisition sysctl this kernel/scope does not
                // expose: not a failure, per the plan.
                Ok(())
            }
            Err(e) => Err(format!("write {path}={}: {e}", sysctl.locked_value())),
        }
    }

    /// Assert no non-loopback IPv6 address and no live IPv6 route survives.
    /// This is [`HandoffStep::VerifyNoIpv6`]'s contract: disabling IPv6 empties
    /// the addresses, but a route (a nexthop-backed one especially) can outlive
    /// the address it was reached through, so both must be checked before
    /// readiness.
    fn verify_no_ipv6() -> Result<(), String> {
        verify_no_ipv6_addresses()?;
        verify_no_ipv6_routes()
    }

    /// No non-loopback IPv6 address. Loopback (`::1`, scope host) is tolerated;
    /// anything else means IPv6 is still live.
    fn verify_no_ipv6_addresses() -> Result<(), String> {
        // /proc/net/if_inet6 columns: address ifindex prefixlen scope flags name.
        let text = match std::fs::read_to_string("/proc/net/if_inet6") {
            Ok(text) => text,
            // Absent means the IPv6 module is not loaded at all: no addresses.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("read /proc/net/if_inet6: {e}")),
        };
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let scope = fields[3];
            let device = fields[5];
            // Scope 0x10 is host (loopback ::1). Tolerate only that.
            if scope.eq_ignore_ascii_case("10") || device == "lo" {
                continue;
            }
            return Err(format!(
                "a non-loopback IPv6 address survives: {} on {} (scope {})",
                fields[0], device, scope
            ));
        }
        Ok(())
    }

    /// No *live* IPv6 route. `/proc/net/ipv6_route` columns are, in order:
    /// destination (32 hex), destination prefix length (hex), source, source
    /// prefix length, next hop, metric, refcount, use count, flags (hex), and
    /// device. A disabled stack still lists the kernel's unreachable/reject
    /// fallbacks (`RTF_REJECT`, not `RTF_UP` — they drop traffic) and possibly
    /// the loopback host route to `::1`; those are tolerated. Any route that is
    /// up, is not a reject, and does not lead to `::1` is a surviving path and
    /// fails the handoff.
    fn verify_no_ipv6_routes() -> Result<(), String> {
        const RTF_UP: u32 = 0x0001;
        const RTF_REJECT: u32 = 0x0200;
        // `::1`, the loopback host address, as the 32-hex column is written.
        const LOOPBACK_DEST: &str = "00000000000000000000000000000001";

        let text = match std::fs::read_to_string("/proc/net/ipv6_route") {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("read /proc/net/ipv6_route: {e}")),
        };
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (dest, dest_prefix, flags_hex, device) =
                (fields[0], fields[1], fields[8], fields[9]);
            let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
            if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
                continue;
            }
            if dest.eq_ignore_ascii_case(LOOPBACK_DEST) {
                continue;
            }
            return Err(format!(
                "a live IPv6 route survives: {dest}/{dest_prefix} dev {device} flags {flags_hex}"
            ));
        }
        Ok(())
    }

    fn drop_bounding_set() -> Result<(), String> {
        let last = cap_last_cap();
        for cap in 0..=last {
            let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if rc != 0 {
                return Err(os_err(&format!("prctl(PR_CAPBSET_DROP, {cap})")));
            }
        }
        Ok(())
    }

    /// `/proc/sys/kernel/cap_last_cap`, or a conservative fallback covering all
    /// capabilities defined at time of writing.
    fn cap_last_cap() -> u32 {
        std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(40)
    }

    fn clear_inheritable_and_ambient() -> Result<(), String> {
        // Ambient first: it is masked by inheritable, so clearing inheritable
        // after leaves nothing to raise.
        let rc = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
        if rc != 0 {
            return Err(os_err("prctl(PR_CAP_AMBIENT_CLEAR_ALL)"));
        }

        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(os_err("capget"));
        }
        data[0].inheritable = 0;
        data[1].inheritable = 0;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(os_err("capset (clear inheritable)"));
        }
        Ok(())
    }

    fn set_no_new_privs() -> Result<(), String> {
        let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(os_err("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
        Ok(())
    }

    fn clear_supplementary_groups() -> Result<(), String> {
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            return Err(os_err("setgroups(0)"));
        }
        Ok(())
    }

    fn set_resgid(gid: u32) -> Result<(), String> {
        let rc = unsafe { libc::setresgid(gid, gid, gid) };
        if rc != 0 {
            return Err(os_err(&format!("setresgid({gid})")));
        }
        Ok(())
    }

    fn set_resuid(uid: u32) -> Result<(), String> {
        let rc = unsafe { libc::setresuid(uid, uid, uid) };
        if rc != 0 {
            return Err(os_err(&format!("setresuid({uid})")));
        }
        Ok(())
    }

    fn verify_locked_identity() -> Result<(), String> {
        let text = std::fs::read_to_string("/proc/self/status")
            .map_err(|e| format!("read /proc/self/status: {e}"))?;
        let status = ProcStatus::parse(&text).map_err(|e| format!("parse status: {e}"))?;
        // SIGUSR1 was blocked in step 1, so the awaiting-release shape — the
        // exact state the host will read from PID 1 — must hold now.
        LockedAwaitingRelease::verify(&status).map_err(|violations| {
            let mut reasons: Vec<String> = violations.iter().map(|v| v.to_string()).collect();
            reasons.sort();
            format!("not the locked identity: {}", reasons.join("; "))
        })?;
        Ok(())
    }

    /// Block `SIGUSR1` so the release wait can be armed for the whole handoff.
    /// The previous mask is deliberately not saved: the workload must run with
    /// `SIGUSR1` *unblocked* whatever the launcher's mask was, so release
    /// unblocks it explicitly (see [`wait_for_release`]) rather than restoring
    /// an inherited mask that might have had it blocked.
    fn arm_sigusr1() -> Result<(), String> {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut set) != 0 {
                return Err(os_err("sigemptyset"));
            }
            if libc::sigaddset(&mut set, libc::SIGUSR1) != 0 {
                return Err(os_err("sigaddset(SIGUSR1)"));
            }
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                return Err(os_err("pthread_sigmask(SIG_BLOCK)"));
            }
        }
        Ok(())
    }

    /// Wait for `SIGUSR1` via a `signalfd`, then unblock it so the workload
    /// does not inherit a blocked signal — regardless of whether the launcher
    /// started PID 1 with it already blocked (`SIG_UNBLOCK` a single-signal
    /// set, not a restore of the inherited mask, which could leave it blocked
    /// and fail [`LockedReleased`](writ_guest_init::proc_status::LockedReleased)).
    ///
    /// `signalfd`, not `sigwait`/`rt_sigtimedwait`: the latter temporarily
    /// clears the waited signal from the thread's *visible* blocked mask for
    /// the duration of the wait, so `/proc/self/status` reads `SigBlk` without
    /// `SIGUSR1` while parked. The host reads exactly that field from PID 1
    /// after `security-ready` and requires `SIGUSR1` blocked
    /// ([`LockedAwaitingRelease`]); a `sigwait`-parked initializer would be
    /// rejected as `Usr1NotBlocked`. `signalfd` leaves the signal blocked in
    /// the mask — visibly so — and dequeues it through the descriptor, which is
    /// the contract the host relies on. (Verified on Linux 6.18: `SigBlk` reads
    /// `0x200` throughout a `signalfd` wait, `0x0` throughout a `sigwait`.)
    fn wait_for_release() -> Result<(), String> {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            // SIGUSR1 is already blocked (armed at startup); signalfd consumes
            // it from the pending set without unblocking it.
            let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC);
            if fd < 0 {
                return Err(os_err("signalfd(SIGUSR1)"));
            }
            let mut buf = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
            loop {
                let n = libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len());
                if n == buf.len() as isize {
                    break;
                }
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    libc::close(fd);
                    return Err(format!("read(signalfd for SIGUSR1): {err}"));
                }
                // A short read cannot deliver a whole siginfo; keep waiting.
            }
            libc::close(fd);
            // Unblock SIGUSR1 for the workload, whatever the launcher's mask
            // was. LockedReleased requires it clear.
            if libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) != 0 {
                return Err(os_err("pthread_sigmask(SIG_UNBLOCK, SIGUSR1)"));
            }
        }
        Ok(())
    }
}
