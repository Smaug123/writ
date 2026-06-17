//! Host-side detection of a network-islanded agent VM.
//!
//! A running agent VM can silently lose its host↔guest network path: the
//! macOS vmnet bridge backing the session's `container` network can go away
//! (e.g. across a host sleep/wake), so the broker gateway alias disappears
//! from every host interface and the guest can no longer reach the broker —
//! while `container network inspect` still reports the network as running.
//!
//! The guest is untrusted once an agent runs, so detection deliberately
//! inspects the *daemon's own* network interfaces rather than probing through
//! the guest. The pure core ([`evaluate_host_path`] + [`ProbeDebounce`]) maps
//! an interface snapshot to a debounced [`NetworkHealth`]; the one imperative
//! edge ([`host_interfaces`]) fills the snapshot from `getifaddrs(3)`. This is
//! a host-side *proxy* for "the guest can reach the broker": it catches the
//! observed failure (the gateway alias / route vanished) but not a subtler
//! case where the alias persists while bridging is silently broken.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Consecutive [`ProbeObservation::Unreachable`] observations required before a
/// session is declared [`NetworkHealth::Unreachable`]. Absorbs a transient blip
/// or a guest reboot window (at the daemon's probe interval).
pub const NETWORK_HEALTH_FAILURE_THRESHOLD: u32 = 3;

/// Whether a session's broker path is currently reachable, as observed from the
/// host. Wire-facing: surfaced in `writ agent-vm list` and stored (as the
/// from/to of a transition) in the audit log.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHealth {
    Reachable,
    Unreachable,
    Unknown,
}

impl NetworkHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// Serde default so a record (or wire message) that predates the field
    /// deserialises as `Unknown` rather than failing.
    pub fn unknown() -> Self {
        Self::Unknown
    }
}

/// A single host-side observation. `Indeterminate` means the snapshot itself
/// could not be taken (e.g. `getifaddrs` failed) — it is explicitly *not*
/// evidence of islanding and never moves the debounced health on its own.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProbeObservation {
    Reachable,
    Unreachable,
    Indeterminate,
}

/// One host network interface (IPv4 only), as the FFI edge produces it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIface {
    pub name: String,
    pub addr: Ipv4Addr,
    pub up: bool,
    pub loopback: bool,
}

/// Pure: is the broker `gateway` bound to a usable (up, non-loopback) host
/// interface in this snapshot? When the vmnet bridge dies the gateway alias
/// disappears from every interface, which we observe here as `Unreachable`.
pub fn evaluate_host_path(ifaces: &[HostIface], gateway: Ipv4Addr) -> ProbeObservation {
    let present = ifaces
        .iter()
        .any(|i| !i.loopback && i.up && i.addr == gateway);
    if present {
        ProbeObservation::Reachable
    } else {
        ProbeObservation::Unreachable
    }
}

/// A change in a session's debounced [`NetworkHealth`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HealthTransition {
    pub from: NetworkHealth,
    pub to: NetworkHealth,
}

impl HealthTransition {
    /// The auditable edge: the session just became unreachable.
    pub fn is_islanding(self) -> bool {
        self.to == NetworkHealth::Unreachable
    }
}

/// Debounced per-session health tracker. Requires
/// [`NETWORK_HEALTH_FAILURE_THRESHOLD`] consecutive `Unreachable` observations
/// before declaring `Unreachable`; any `Reachable` resets it; `Indeterminate`
/// is a no-op.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDebounce {
    health: NetworkHealth,
    consecutive_failures: u32,
}

impl Default for ProbeDebounce {
    fn default() -> Self {
        Self {
            health: NetworkHealth::Unknown,
            consecutive_failures: 0,
        }
    }
}

impl ProbeDebounce {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn health(&self) -> NetworkHealth {
        self.health
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Fold one observation in. Returns `Some(transition)` iff the surfaced
    /// `health` value changed (so the daemon can audit only on transitions, not
    /// on every probe).
    pub fn observe(&mut self, observation: ProbeObservation) -> Option<HealthTransition> {
        let from = self.health;
        match observation {
            ProbeObservation::Reachable => {
                self.consecutive_failures = 0;
                self.health = NetworkHealth::Reachable;
            }
            ProbeObservation::Unreachable => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                if self.consecutive_failures >= NETWORK_HEALTH_FAILURE_THRESHOLD {
                    self.health = NetworkHealth::Unreachable;
                }
            }
            ProbeObservation::Indeterminate => {}
        }
        (self.health != from).then_some(HealthTransition {
            from,
            to: self.health,
        })
    }
}

/// Snapshot the host's IPv4 interfaces via `getifaddrs(3)`.
///
/// This is the only `unsafe` in the module: it interprets the kernel's
/// interface list into plain [`HostIface`] data the pure core consumes. It
/// never touches the guest. Callers map an `Err` to
/// [`ProbeObservation::Indeterminate`] (a failed snapshot is not evidence of
/// islanding).
#[cfg(unix)]
pub fn host_interfaces() -> std::io::Result<Vec<HostIface>> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a freshly-allocated list head into `head` on
    // success (rc 0) and leaves it untouched on failure.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Free the list on every return path, including a panic in the loop.
    struct FreeOnDrop(*mut libc::ifaddrs);
    impl Drop for FreeOnDrop {
        fn drop(&mut self) {
            // SAFETY: `self.0` is the head returned by a successful `getifaddrs`
            // and is freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = FreeOnDrop(head);

    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points to a valid node in the list.
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;

        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null; reading the family tag is valid for
        // any sockaddr.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }
        // SAFETY: family is AF_INET, so `ifa_addr` points to a `sockaddr_in`.
        let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        // `s_addr` is in network byte order; its in-memory bytes are the octets
        // in order, so `to_ne_bytes` yields them endian-independently.
        let addr = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());

        let name = if entry.ifa_name.is_null() {
            String::new()
        } else {
            // SAFETY: when non-null, `ifa_name` is a NUL-terminated C string.
            unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned()
        };

        let flags = entry.ifa_flags as i32;
        out.push(HostIface {
            name,
            addr,
            up: flags & libc::IFF_UP != 0,
            loopback: flags & libc::IFF_LOOPBACK != 0,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn iface(name: &str, addr: [u8; 4], up: bool, loopback: bool) -> HostIface {
        HostIface {
            name: name.to_string(),
            addr: Ipv4Addr::from(addr),
            up,
            loopback,
        }
    }

    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 252, 1);

    #[test]
    fn evaluate_reachable_when_gateway_bound_to_up_iface() {
        let ifaces = vec![
            iface("lo0", [127, 0, 0, 1], true, true),
            iface("vmenet0", [192, 168, 252, 1], true, false),
        ];
        assert_eq!(evaluate_host_path(&ifaces, GW), ProbeObservation::Reachable);
    }

    #[test]
    fn evaluate_unreachable_when_gateway_absent() {
        // The observed failure: gateway alias gone from every interface.
        let ifaces = vec![
            iface("lo0", [127, 0, 0, 1], true, true),
            iface("en0", [192, 168, 8, 180], true, false),
        ];
        assert_eq!(
            evaluate_host_path(&ifaces, GW),
            ProbeObservation::Unreachable
        );
    }

    #[test]
    fn evaluate_unreachable_when_gateway_only_on_down_or_loopback_iface() {
        let down = vec![iface("vmenet0", [192, 168, 252, 1], false, false)];
        assert_eq!(evaluate_host_path(&down, GW), ProbeObservation::Unreachable);
        let loopback_only = vec![iface("lo0", [192, 168, 252, 1], true, true)];
        assert_eq!(
            evaluate_host_path(&loopback_only, GW),
            ProbeObservation::Unreachable
        );
    }

    #[test]
    fn evaluate_empty_snapshot_is_unreachable() {
        assert_eq!(evaluate_host_path(&[], GW), ProbeObservation::Unreachable);
    }

    fn obs() -> impl Strategy<Value = ProbeObservation> {
        prop_oneof![
            Just(ProbeObservation::Reachable),
            Just(ProbeObservation::Unreachable),
            Just(ProbeObservation::Indeterminate),
        ]
    }

    proptest! {
        // A single Reachable always wins: health Reachable, counter cleared.
        #[test]
        fn reachable_resets(seq in proptest::collection::vec(obs(), 0..40)) {
            let mut d = ProbeDebounce::new();
            for o in seq {
                d.observe(o);
            }
            d.observe(ProbeObservation::Reachable);
            prop_assert_eq!(d.health(), NetworkHealth::Reachable);
            prop_assert_eq!(d.consecutive_failures(), 0);
        }

        // It takes exactly THRESHOLD consecutive Unreachable from a fresh
        // tracker to declare Unreachable — not one fewer.
        #[test]
        fn threshold_is_exact(n in 0u32..NETWORK_HEALTH_FAILURE_THRESHOLD) {
            let mut d = ProbeDebounce::new();
            for _ in 0..n {
                d.observe(ProbeObservation::Unreachable);
            }
            prop_assert_ne!(d.health(), NetworkHealth::Unreachable);
            // The remaining failures up to the threshold flip it.
            for _ in n..NETWORK_HEALTH_FAILURE_THRESHOLD {
                d.observe(ProbeObservation::Unreachable);
            }
            prop_assert_eq!(d.health(), NetworkHealth::Unreachable);
        }

        // Indeterminate is a pure no-op: folding a sequence yields the same
        // health and counter as folding it with all Indeterminates removed.
        #[test]
        fn indeterminate_is_noop(seq in proptest::collection::vec(obs(), 0..40)) {
            let mut with = ProbeDebounce::new();
            for o in &seq {
                with.observe(*o);
            }
            let mut without = ProbeDebounce::new();
            for o in seq.iter().filter(|o| **o != ProbeObservation::Indeterminate) {
                without.observe(*o);
            }
            prop_assert_eq!(with, without);
        }

        // At most one islanding transition can occur without an intervening
        // recovery (a transition whose `to` is not Unreachable).
        #[test]
        fn no_double_islanding_without_recovery(seq in proptest::collection::vec(obs(), 0..60)) {
            let mut d = ProbeDebounce::new();
            let mut islanded = false;
            for o in seq {
                if let Some(t) = d.observe(o) {
                    if t.is_islanding() {
                        prop_assert!(!islanded, "two islanding transitions without recovery");
                        islanded = true;
                    } else {
                        islanded = false;
                    }
                }
            }
        }

        // `observe` only ever reports a transition when the health value
        // actually changed.
        #[test]
        fn transition_iff_health_changed(seq in proptest::collection::vec(obs(), 0..40)) {
            let mut d = ProbeDebounce::new();
            for o in seq {
                let before = d.health();
                let t = d.observe(o);
                let after = d.health();
                prop_assert_eq!(t.is_some(), before != after);
                if let Some(t) = t {
                    prop_assert_eq!(t.from, before);
                    prop_assert_eq!(t.to, after);
                }
            }
        }
    }

    // The FFI edge: loopback is always present and up on a sane host, and the
    // pure core agrees that 127.0.0.1 is "reachable" against that real snapshot.
    #[cfg(unix)]
    #[test]
    fn host_interfaces_reports_loopback() {
        let ifaces = host_interfaces().expect("getifaddrs should succeed");
        let lo = ifaces
            .iter()
            .find(|i| i.addr == Ipv4Addr::LOCALHOST)
            .expect("loopback 127.0.0.1 should be present");
        assert!(lo.up, "loopback should be up");
        assert!(lo.loopback, "loopback should carry IFF_LOOPBACK");
        assert_eq!(
            evaluate_host_path(&ifaces, Ipv4Addr::new(203, 0, 113, 1)),
            ProbeObservation::Unreachable,
            "an unbound TEST-NET-3 gateway must read as unreachable"
        );
    }
}
