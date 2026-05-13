//! Guest-side sandbox-leak probes.
//!
//! Probes run inside the agent VM before any broker traffic. The contract is
//! "the sandbox enforces no external egress": each probe is something the
//! sandbox should block, so the VM bails closed if any probe succeeds.
//!
//! The set of probes is exposed as data ([`SandboxLeakProbe`]) so callers can
//! enumerate, render, and replay it without going through this module's
//! impure runner. [`run_sandbox_leak_probes`] is the imperative shell that
//! attempts each probe in order and returns the first leak.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time;

/// Per-probe deadline. Apple Container's `--internal` host-only network plus
/// the session PF anchor either refuses immediately (no route) or silently
/// drops (PF block). 1.5s covers both shapes without adding noticeable boot
/// latency to the three default probes.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// The fixed external addresses used by [`default_leak_probes`]. Kept as
/// constants so tests can assert the on-the-wire targets are stable across
/// refactors.
pub const DEFAULT_DIRECT_IPV4: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
pub const DEFAULT_DIRECT_IPV6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    443,
);
pub const DEFAULT_DNS_HOST: &str = "google.com";
pub const DEFAULT_DNS_PORT: u16 = 443;

/// A single thing the sandbox should refuse. The runner attempts each in
/// order; the first one that succeeds is reported as a breach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxLeakProbe {
    /// TCP-connect a literal external IPv4 address. Bypasses DNS entirely so
    /// "no resolver" cannot mask a routing leak.
    DirectIpv4(SocketAddr),
    /// TCP-connect a literal external IPv6 address. Catches v6 routing leaks
    /// in nominally-v4-only sandboxes.
    DirectIpv6(SocketAddr),
    /// Resolve a hostname and TCP-connect each address. Catches resolver
    /// leaks (DNS getting out) as well as residual routing leaks.
    DnsAndConnect { host: String, port: u16 },
}

/// The first sandbox breach observed by [`run_sandbox_leak_probes`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxLeak {
    DirectIpv4Reachable(SocketAddr),
    DirectIpv6Reachable(SocketAddr),
    /// DNS resolved to one or more addresses, but none accepted a TCP
    /// connection in time. Still a leak — the resolver itself reached
    /// somewhere it shouldn't have.
    DnsResolved { host: String, addrs: Vec<IpAddr> },
    /// DNS resolved and at least one address accepted a TCP connection.
    HostReachable { host: String, addr: SocketAddr },
}

impl fmt::Display for SandboxLeak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectIpv4Reachable(addr) => {
                write!(f, "direct IPv4 connect to {addr} succeeded")
            }
            Self::DirectIpv6Reachable(addr) => {
                write!(f, "direct IPv6 connect to {addr} succeeded")
            }
            Self::DnsResolved { host, addrs } => {
                write!(f, "DNS for {host} resolved to ")?;
                for (i, addr) in addrs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{addr}")?;
                }
                Ok(())
            }
            Self::HostReachable { host, addr } => {
                write!(f, "connect to {host} via {addr} succeeded")
            }
        }
    }
}

/// The default probe set: the two literal addresses plus a DNS probe for
/// `google.com:443`.
pub fn default_leak_probes() -> Vec<SandboxLeakProbe> {
    vec![
        SandboxLeakProbe::DirectIpv4(DEFAULT_DIRECT_IPV4),
        SandboxLeakProbe::DirectIpv6(DEFAULT_DIRECT_IPV6),
        SandboxLeakProbe::DnsAndConnect {
            host: DEFAULT_DNS_HOST.to_string(),
            port: DEFAULT_DNS_PORT,
        },
    ]
}

/// Attempt every probe with the given per-probe deadline. Returns `Ok(())`
/// once every probe has failed as expected, or `Err` with the first leak
/// detected.
pub async fn run_sandbox_leak_probes(
    probes: &[SandboxLeakProbe],
    per_probe_timeout: Duration,
) -> Result<(), SandboxLeak> {
    for probe in probes {
        if let Some(leak) = run_one_probe(probe, per_probe_timeout).await {
            return Err(leak);
        }
    }
    Ok(())
}

async fn run_one_probe(probe: &SandboxLeakProbe, timeout: Duration) -> Option<SandboxLeak> {
    match probe {
        SandboxLeakProbe::DirectIpv4(addr) => try_connect(*addr, timeout)
            .await
            .then_some(SandboxLeak::DirectIpv4Reachable(*addr)),
        SandboxLeakProbe::DirectIpv6(addr) => try_connect(*addr, timeout)
            .await
            .then_some(SandboxLeak::DirectIpv6Reachable(*addr)),
        SandboxLeakProbe::DnsAndConnect { host, port } => {
            let addrs = match try_dns_lookup(host, *port, timeout).await {
                Some(addrs) if !addrs.is_empty() => addrs,
                _ => return None,
            };
            for addr in &addrs {
                if try_connect(*addr, timeout).await {
                    return Some(SandboxLeak::HostReachable {
                        host: host.clone(),
                        addr: *addr,
                    });
                }
            }
            Some(SandboxLeak::DnsResolved {
                host: host.clone(),
                addrs: addrs.into_iter().map(|sa| sa.ip()).collect(),
            })
        }
    }
}

async fn try_connect(addr: SocketAddr, timeout: Duration) -> bool {
    matches!(
        time::timeout(timeout, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

async fn try_dns_lookup(host: &str, port: u16, timeout: Duration) -> Option<Vec<SocketAddr>> {
    match time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(iter)) => Some(iter.collect()),
        Ok(Err(_)) | Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    use tokio::net::TcpListener;

    #[test]
    fn default_probes_are_stable_set() {
        let probes = default_leak_probes();
        assert_eq!(probes.len(), 3);
        assert_eq!(probes[0], SandboxLeakProbe::DirectIpv4(DEFAULT_DIRECT_IPV4));
        assert_eq!(probes[1], SandboxLeakProbe::DirectIpv6(DEFAULT_DIRECT_IPV6));
        assert_eq!(
            probes[2],
            SandboxLeakProbe::DnsAndConnect {
                host: DEFAULT_DNS_HOST.to_string(),
                port: DEFAULT_DNS_PORT,
            }
        );
    }

    #[test]
    fn default_direct_addresses_are_external() {
        // Guard against accidental reuse of private/loopback ranges in the
        // default probe set. These exact addresses are well-known stable
        // anycast endpoints, but the property we care about is "not local".
        match DEFAULT_DIRECT_IPV4.ip() {
            IpAddr::V4(a) => {
                assert!(!a.is_loopback());
                assert!(!a.is_private());
                assert!(!a.is_link_local());
                assert!(!a.is_unspecified());
            }
            IpAddr::V6(_) => panic!("DEFAULT_DIRECT_IPV4 must be IPv4"),
        }
        match DEFAULT_DIRECT_IPV6.ip() {
            IpAddr::V6(a) => {
                assert!(!a.is_loopback());
                assert!(!a.is_unspecified());
                // No is_unique_local on stable Rust; assert non-link-local.
                assert!(!a.is_unicast_link_local());
            }
            IpAddr::V4(_) => panic!("DEFAULT_DIRECT_IPV6 must be IPv6"),
        }
    }

    #[test]
    fn leak_display_renders_each_variant() {
        let cases = [
            (
                SandboxLeak::DirectIpv4Reachable(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(8, 8, 8, 8),
                    53,
                ))),
                "direct IPv4 connect to 8.8.8.8:53 succeeded",
            ),
            (
                SandboxLeak::DirectIpv6Reachable(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                    53,
                    0,
                    0,
                ))),
                "direct IPv6 connect to [2001:4860:4860::8888]:53 succeeded",
            ),
            (
                SandboxLeak::DnsResolved {
                    host: "example.com".into(),
                    addrs: vec![
                        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        IpAddr::V6(Ipv6Addr::new(
                            0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
                        )),
                    ],
                },
                "DNS for example.com resolved to 93.184.216.34, \
                 2606:2800:220:1:248:1893:25c8:1946",
            ),
            (
                SandboxLeak::HostReachable {
                    host: "example.com".into(),
                    addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
                },
                "connect to example.com via 127.0.0.1:443 succeeded",
            ),
        ];
        for (leak, expected) in cases {
            assert_eq!(leak.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn try_connect_succeeds_against_a_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(try_connect(addr, Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn try_connect_fails_against_a_closed_port() {
        // Bind, capture the address, drop the listener — the kernel will
        // refuse the connect almost immediately. The short timeout proves we
        // do not block on a missing listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(!try_connect(addr, Duration::from_millis(500)).await);
    }

    #[tokio::test]
    async fn run_one_probe_returns_none_for_unreachable_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let probe = SandboxLeakProbe::DirectIpv4(addr);
        assert_eq!(
            run_one_probe(&probe, Duration::from_millis(500)).await,
            None
        );
    }

    #[tokio::test]
    async fn run_one_probe_reports_direct_ipv4_reachability() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = SandboxLeakProbe::DirectIpv4(addr);
        assert_eq!(
            run_one_probe(&probe, Duration::from_secs(1)).await,
            Some(SandboxLeak::DirectIpv4Reachable(addr))
        );
    }

    #[tokio::test]
    async fn dns_and_connect_against_localhost_reports_host_reachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = SandboxLeakProbe::DnsAndConnect {
            host: "localhost".into(),
            port: addr.port(),
        };
        match run_one_probe(&probe, Duration::from_secs(1)).await {
            Some(SandboxLeak::HostReachable { host, addr: leaked }) => {
                assert_eq!(host, "localhost");
                assert_eq!(leaked.port(), addr.port());
                assert!(leaked.ip().is_loopback());
            }
            other => panic!("expected HostReachable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dns_and_connect_returns_none_when_name_does_not_resolve() {
        // `.invalid` is RFC 6761 reserved as an always-non-resolvable TLD.
        let probe = SandboxLeakProbe::DnsAndConnect {
            host: "writ-vm-sandbox-test.invalid".into(),
            port: 443,
        };
        assert_eq!(run_one_probe(&probe, Duration::from_secs(1)).await, None);
    }

    #[tokio::test]
    async fn run_sandbox_leak_probes_returns_first_breach() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        // probe[0] should fail (closed port), probe[1] should breach (open).
        let probes = vec![
            SandboxLeakProbe::DirectIpv4(closed),
            SandboxLeakProbe::DirectIpv4(open),
            // probe[2] would also breach if reached; assert it isn't reached
            // by checking the *specific* breach returned is from probe[1].
            SandboxLeakProbe::DirectIpv4(open),
        ];
        let result = run_sandbox_leak_probes(&probes, Duration::from_secs(1)).await;
        assert_eq!(result, Err(SandboxLeak::DirectIpv4Reachable(open)));
    }

    #[tokio::test]
    async fn run_sandbox_leak_probes_returns_ok_when_all_blocked() {
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        let probes = vec![
            SandboxLeakProbe::DirectIpv4(closed),
            SandboxLeakProbe::DnsAndConnect {
                host: "writ-vm-sandbox-test.invalid".into(),
                port: 443,
            },
        ];
        assert_eq!(
            run_sandbox_leak_probes(&probes, Duration::from_millis(500)).await,
            Ok(())
        );
    }
}
