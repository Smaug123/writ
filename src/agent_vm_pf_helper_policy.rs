//! The PF helper's policy file: the bounds the privileged helper validates
//! every session against, read from a fixed root-owned path rather than
//! taken from the unprivileged caller.
//!
//! The helper runs under `sudo` for `writd`. Until protocol v2, the pools and
//! the broker-port range it validated a session's subnet and ports against
//! were command-line arguments, so the caller it was meant to bound was the
//! one supplying the bounds: a compromised daemon could name any RFC1918 pool
//! and any port range and the helper would load rules for them. The policy
//! file closes that. It lives at [`PF_HELPER_POLICY_PATH`], and the helper
//! refuses to run unless it is a root-owned regular file, reached without
//! following a symlink at the final component, writable by neither group nor
//! world, in a directory that is likewise root-owned and unwritable by others.
//! The session facts that remain arguments (session id, subnet, ports, broker
//! host) are validated against the file exactly as they were validated against
//! the arguments before.
//!
//! The file must agree with `writd`'s own `agent_vm.lifecycle` pools and
//! `agent_vm.vm_http` port range: a subnet the daemon allocates outside the
//! policy's pool is refused by the helper, which is the point.
//!
//! The admitted interface-name policy (which host interfaces the IPv6 deny may
//! ever scope to) is *not* in this file: it stays compiled into the discovery
//! (`bridgeN` with `vmenetN` members, see `parse_bridge_for_gateway`), because
//! a fixed rule is stronger than a configurable one and there is no second
//! interface shape to admit.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::{AgentNetworkPool, AgentVmConfigError, BrokerPortRange, Ipv4Cidr, Ipv6Cidr};

/// Where the privileged helper reads its policy. Fixed on purpose: a
/// caller-chosen path would hand the bounds back to the caller.
pub const PF_HELPER_POLICY_PATH: &str = "/etc/writ/agent-vm-pf-policy.json";

/// The owner the production helper requires of the policy file and its
/// directory.
pub const PF_HELPER_POLICY_REQUIRED_OWNER: u32 = 0;

/// The policy file is a few hundred bytes; anything past this is not one.
pub const PF_HELPER_POLICY_MAX_BYTES: u64 = 64 * 1024;

/// The policy file format this build reads.
pub const PF_HELPER_POLICY_FORMAT_VERSION: u16 = 1;

/// The bounds every session install and removal is validated against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PfHelperPolicy {
    pool: AgentNetworkPool,
    broker_port_range: BrokerPortRange,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u16,
    ipv4_pool: String,
    ipv6_pool: String,
    broker_port_min: u16,
    broker_port_max: u16,
}

/// Why the policy file was refused. Every variant names the path, because the
/// helper's error is what an operator sees when a session will not start.
#[derive(Debug, thiserror::Error)]
pub enum PfHelperPolicyError {
    #[error("PF helper policy file {path} does not exist")]
    Missing { path: PathBuf },
    #[error("PF helper policy file {path} is a symbolic link; it must be a regular file")]
    Symlink { path: PathBuf },
    #[error("cannot open PF helper policy file {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("PF helper policy file {path} is not a regular file")]
    NotRegular { path: PathBuf },
    #[error(
        "PF helper policy file {path} is owned by uid {uid}; it must be owned by uid {required}"
    )]
    WrongOwner {
        path: PathBuf,
        uid: u32,
        required: u32,
    },
    #[error(
        "PF helper policy file {path} has mode {mode:o}; it must not be writable by group or world"
    )]
    Writable { path: PathBuf, mode: u32 },
    #[error("cannot inspect the directory {path} holding the PF helper policy file: {source}")]
    Directory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the directory {path} holding the PF helper policy file is not a directory")]
    DirectoryNotDirectory { path: PathBuf },
    #[error(
        "the directory {path} holding the PF helper policy file is owned by uid {uid}; it must \
         be owned by uid {required}"
    )]
    DirectoryWrongOwner {
        path: PathBuf,
        uid: u32,
        required: u32,
    },
    #[error(
        "the directory {path} holding the PF helper policy file has mode {mode:o}; it must not \
         be writable by group or world"
    )]
    DirectoryWritable { path: PathBuf, mode: u32 },
    #[error("PF helper policy file {path} is larger than {cap} bytes")]
    TooLarge { path: PathBuf, cap: u64 },
    #[error("cannot read PF helper policy file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("PF helper policy file {path} is not valid policy JSON: {source}")]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "PF helper policy file {path} has format version {version}; this helper reads version \
         {PF_HELPER_POLICY_FORMAT_VERSION}"
    )]
    UnsupportedVersion { path: PathBuf, version: u16 },
    #[error("PF helper policy file {path} field {field} is not a CIDR: {reason}")]
    InvalidCidr {
        path: PathBuf,
        field: &'static str,
        reason: String,
    },
    #[error("PF helper policy file {path} is not a valid policy: {source}")]
    Invalid {
        path: PathBuf,
        #[source]
        source: AgentVmConfigError,
    },
}

impl PfHelperPolicy {
    pub fn new(pool: AgentNetworkPool, broker_port_range: BrokerPortRange) -> Self {
        Self {
            pool,
            broker_port_range,
        }
    }

    pub fn pool(self) -> AgentNetworkPool {
        self.pool
    }

    pub fn broker_port_range(self) -> BrokerPortRange {
        self.broker_port_range
    }

    /// The canonical file contents for this policy: what the documentation
    /// tells an operator to write, and what [`Self::parse`] reads back.
    pub fn render(self) -> String {
        let wire = Wire {
            version: PF_HELPER_POLICY_FORMAT_VERSION,
            ipv4_pool: self.pool.ipv4_base().to_string(),
            ipv6_pool: self.pool.ipv6_base().to_string(),
            broker_port_min: self.broker_port_range.min().get(),
            broker_port_max: self.broker_port_range.max().get(),
        };
        let mut text = serde_json::to_string_pretty(&wire)
            .expect("a struct of strings and integers always serialises");
        text.push('\n');
        text
    }

    /// Parse policy file contents. Whitespace and key order are free (an
    /// operator writes this file by hand); unknown fields, another format
    /// version, an unparseable CIDR, and any bound the core refuses (a
    /// non-private pool, an inverted or privileged port range) are errors.
    pub fn parse(path: &Path, text: &str) -> Result<Self, PfHelperPolicyError> {
        let wire: Wire =
            serde_json::from_str(text).map_err(|source| PfHelperPolicyError::Malformed {
                path: path.to_path_buf(),
                source,
            })?;
        if wire.version != PF_HELPER_POLICY_FORMAT_VERSION {
            return Err(PfHelperPolicyError::UnsupportedVersion {
                path: path.to_path_buf(),
                version: wire.version,
            });
        }
        let cidr_err = |field, reason: String| PfHelperPolicyError::InvalidCidr {
            path: path.to_path_buf(),
            field,
            reason,
        };
        let ipv4_pool =
            parse_ipv4_cidr(&wire.ipv4_pool).map_err(|reason| cidr_err("ipv4_pool", reason))?;
        let ipv6_pool =
            parse_ipv6_cidr(&wire.ipv6_pool).map_err(|reason| cidr_err("ipv6_pool", reason))?;
        let invalid = |source| PfHelperPolicyError::Invalid {
            path: path.to_path_buf(),
            source,
        };
        Ok(Self {
            pool: AgentNetworkPool::new(ipv4_pool, ipv6_pool).map_err(invalid)?,
            broker_port_range: BrokerPortRange::new(wire.broker_port_min, wire.broker_port_max)
                .map_err(invalid)?,
        })
    }
}

/// Parse `a.b.c.d/n` into a validated CIDR (host bits must be zero).
pub fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr, String> {
    let (addr, prefix) = split_cidr(raw)?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("invalid IPv4 address in {raw:?}: {e}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| format!("invalid prefix length in {raw:?}: {e}"))?;
    Ipv4Cidr::new(addr, prefix).map_err(|e| e.to_string())
}

/// Parse `addr/n` into a validated IPv6 CIDR (host bits must be zero).
pub fn parse_ipv6_cidr(raw: &str) -> Result<Ipv6Cidr, String> {
    let (addr, prefix) = split_cidr(raw)?;
    let addr = addr
        .parse::<Ipv6Addr>()
        .map_err(|e| format!("invalid IPv6 address in {raw:?}: {e}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| format!("invalid prefix length in {raw:?}: {e}"))?;
    Ipv6Cidr::new(addr, prefix).map_err(|e| e.to_string())
}

fn split_cidr(raw: &str) -> Result<(&str, &str), String> {
    raw.split_once('/')
        .ok_or_else(|| format!("CIDR value must contain '/', got {raw:?}"))
}

/// Mode bits that let anyone but the owner write: group or world.
const WRITABLE_BY_OTHERS: u32 = 0o022;

/// Load the policy at `path`, refusing anything but a regular file owned by
/// `required_owner` (uid), writable by nobody else, reached without following
/// a symlink at the final component, in a directory owned by `required_owner`
/// and writable by nobody else. Production passes
/// [`PF_HELPER_POLICY_REQUIRED_OWNER`]; tests in a temporary directory pass
/// their own uid, which is the only reason the owner is a parameter.
///
/// The checks run on the opened file's descriptor (`fstat`), not on the path,
/// so the file inspected is the file read.
pub fn load_pf_helper_policy(
    path: &Path,
    required_owner: u32,
) -> Result<PfHelperPolicy, PfHelperPolicyError> {
    let owned = || path.to_path_buf();
    let mut file = match File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(PfHelperPolicyError::Missing { path: owned() });
        }
        // `O_NOFOLLOW` on a symlink fails with ELOOP on both Linux and macOS.
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
            return Err(PfHelperPolicyError::Symlink { path: owned() });
        }
        Err(source) => {
            return Err(PfHelperPolicyError::Open {
                path: owned(),
                source,
            });
        }
    };
    let meta = file
        .metadata()
        .map_err(|source| PfHelperPolicyError::Open {
            path: owned(),
            source,
        })?;
    if !meta.file_type().is_file() {
        return Err(PfHelperPolicyError::NotRegular { path: owned() });
    }
    if meta.uid() != required_owner {
        return Err(PfHelperPolicyError::WrongOwner {
            path: owned(),
            uid: meta.uid(),
            required: required_owner,
        });
    }
    if meta.mode() & WRITABLE_BY_OTHERS != 0 {
        return Err(PfHelperPolicyError::Writable {
            path: owned(),
            mode: meta.mode() & 0o7777,
        });
    }
    // The directory: a writable one would let another user replace the file
    // (a rename does not need write access to the file itself). Its own
    // symlink-ness is not a concern — `/etc` is a symlink on macOS — since
    // what matters is who can write into the directory the name resolves to.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir_meta = std::fs::metadata(&dir).map_err(|source| PfHelperPolicyError::Directory {
        path: dir.clone(),
        source,
    })?;
    if !dir_meta.file_type().is_dir() {
        return Err(PfHelperPolicyError::DirectoryNotDirectory { path: dir });
    }
    if dir_meta.uid() != required_owner {
        return Err(PfHelperPolicyError::DirectoryWrongOwner {
            path: dir,
            uid: dir_meta.uid(),
            required: required_owner,
        });
    }
    if dir_meta.mode() & WRITABLE_BY_OTHERS != 0 {
        return Err(PfHelperPolicyError::DirectoryWritable {
            path: dir,
            mode: dir_meta.mode() & 0o7777,
        });
    }
    if meta.len() > PF_HELPER_POLICY_MAX_BYTES {
        return Err(PfHelperPolicyError::TooLarge {
            path: owned(),
            cap: PF_HELPER_POLICY_MAX_BYTES,
        });
    }
    let mut text = String::new();
    // Bounded even if the file grows between the size check and the read.
    (&mut file)
        .take(PF_HELPER_POLICY_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| PfHelperPolicyError::Read {
            path: owned(),
            source,
        })?;
    if text.len() as u64 > PF_HELPER_POLICY_MAX_BYTES {
        return Err(PfHelperPolicyError::TooLarge {
            path: owned(),
            cap: PF_HELPER_POLICY_MAX_BYTES,
        });
    }
    PfHelperPolicy::parse(path, &text)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use proptest::prelude::*;

    use super::*;
    use crate::agent_vm_firewall::{SessionFirewallRemoval, SessionFirewallSpec};
    use crate::core::{BrokerPort, BrokerPorts, SessionId};

    fn arb_ipv4_base_in(
        range_base: Ipv4Addr,
        range_prefix: u8,
        max_prefix: u8,
    ) -> BoxedStrategy<Ipv4Cidr> {
        (range_prefix..=max_prefix)
            .prop_flat_map(move |prefix| {
                let slots = 1u32 << (prefix - range_prefix);
                (Just(prefix), 0u32..slots)
            })
            .prop_map(move |(prefix, slot)| {
                let raw = u32::from(range_base) + (slot << (32 - prefix));
                Ipv4Cidr::new(Ipv4Addr::from(raw), prefix).unwrap()
            })
            .boxed()
    }

    fn arb_private_ipv4_pool() -> impl Strategy<Value = Ipv4Cidr> {
        prop_oneof![
            arb_ipv4_base_in(Ipv4Addr::new(10, 0, 0, 0), 8, 24),
            arb_ipv4_base_in(Ipv4Addr::new(172, 16, 0, 0), 12, 24),
            arb_ipv4_base_in(Ipv4Addr::new(192, 168, 0, 0), 16, 24),
        ]
    }

    fn arb_ula_ipv6_pool() -> impl Strategy<Value = Ipv6Cidr> {
        (7u8..=64)
            .prop_flat_map(|prefix| {
                let slots = 1u64 << (prefix - 7);
                (Just(prefix), 0u64..slots)
            })
            .prop_map(|(prefix, slot)| {
                let raw = (0xfc00u128 << 112) + (u128::from(slot) << (128 - prefix));
                Ipv6Cidr::new(Ipv6Addr::from(raw), prefix).unwrap()
            })
    }

    fn arb_port_range() -> impl Strategy<Value = BrokerPortRange> {
        (1024u16..=u16::MAX, 1024u16..=u16::MAX)
            .prop_map(|(a, b)| BrokerPortRange::new(a.min(b), a.max(b)).unwrap())
    }

    pub(crate) fn arb_policy() -> impl Strategy<Value = PfHelperPolicy> {
        (
            arb_private_ipv4_pool(),
            arb_ula_ipv6_pool(),
            arb_port_range(),
        )
            .prop_map(|(v4, v6, range)| {
                PfHelperPolicy::new(AgentNetworkPool::new(v4, v6).unwrap(), range)
            })
    }

    fn policy() -> PfHelperPolicy {
        PfHelperPolicy::new(
            AgentNetworkPool::new(
                parse_ipv4_cidr("10.200.0.0/16").unwrap(),
                parse_ipv6_cidr("fd00:7772:6974::/48").unwrap(),
            )
            .unwrap(),
            BrokerPortRange::new(49152, 65535).unwrap(),
        )
    }

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    /// Write `contents` as the policy file in a fresh private directory, with
    /// the given mode.
    fn write_policy(dir: &Path, contents: &str, mode: u32) -> PathBuf {
        let path = dir.join("agent-vm-pf-policy.json");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn the_documented_policy_renders_to_the_documented_file() {
        assert_eq!(
            policy().render(),
            "{\n  \"version\": 1,\n  \"ipv4_pool\": \"10.200.0.0/16\",\n  \"ipv6_pool\": \"fd00:7772:6974::/48\",\n  \"broker_port_min\": 49152,\n  \"broker_port_max\": 65535\n}\n"
        );
    }

    #[test]
    fn a_root_owned_looking_file_in_a_private_directory_loads() {
        let dir = private_dir();
        let path = write_policy(dir.path(), &policy().render(), 0o644);
        assert_eq!(load_pf_helper_policy(&path, me()).unwrap(), policy());
    }

    #[test]
    fn each_refusal_names_its_reason() {
        let dir = private_dir();
        let path = dir.path().join("agent-vm-pf-policy.json");
        assert!(matches!(
            load_pf_helper_policy(&path, me()),
            Err(PfHelperPolicyError::Missing { .. })
        ));

        // A symlink to a perfectly good file is refused at the final component.
        let target = write_policy(dir.path(), &policy().render(), 0o644);
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            load_pf_helper_policy(&link, me()),
            Err(PfHelperPolicyError::Symlink { .. })
        ));

        // Not a regular file.
        let subdir = dir.path().join("dir.json");
        std::fs::create_dir(&subdir).unwrap();
        assert!(matches!(
            load_pf_helper_policy(&subdir, me()),
            Err(PfHelperPolicyError::NotRegular { .. })
        ));

        // Wrong owner: the file is ours, and we require someone else.
        assert!(matches!(
            load_pf_helper_policy(&target, me().wrapping_add(1)),
            Err(PfHelperPolicyError::WrongOwner { .. })
        ));

        // Group- or world-writable.
        for mode in [0o664, 0o646, 0o666] {
            let path = write_policy(dir.path(), &policy().render(), mode);
            assert!(
                matches!(
                    load_pf_helper_policy(&path, me()),
                    Err(PfHelperPolicyError::Writable { .. })
                ),
                "mode {mode:o}"
            );
        }

        // Too large, even if what fits would parse.
        let mut big = policy().render();
        big.push_str(&" ".repeat(PF_HELPER_POLICY_MAX_BYTES as usize));
        let path = write_policy(dir.path(), &big, 0o644);
        assert!(matches!(
            load_pf_helper_policy(&path, me()),
            Err(PfHelperPolicyError::TooLarge { .. })
        ));

        // Unparseable, unknown field, wrong version, bad CIDR, bad bounds.
        type Verdict = fn(&PfHelperPolicyError) -> bool;
        let cases: [(&str, Verdict); 7] = [
            ("{", |e| matches!(e, PfHelperPolicyError::Malformed { .. })),
            (
                r#"{"version":1,"ipv4_pool":"10.200.0.0/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":49152,"broker_port_max":65535,"extra":1}"#,
                |e| matches!(e, PfHelperPolicyError::Malformed { .. }),
            ),
            (
                r#"{"version":2,"ipv4_pool":"10.200.0.0/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":49152,"broker_port_max":65535}"#,
                |e| {
                    matches!(
                        e,
                        PfHelperPolicyError::UnsupportedVersion { version: 2, .. }
                    )
                },
            ),
            (
                r#"{"version":1,"ipv4_pool":"10.200.0.1/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":49152,"broker_port_max":65535}"#,
                |e| {
                    matches!(
                        e,
                        PfHelperPolicyError::InvalidCidr {
                            field: "ipv4_pool",
                            ..
                        }
                    )
                },
            ),
            (
                r#"{"version":1,"ipv4_pool":"10.200.0.0/16","ipv6_pool":"fd00:7772:6974::","broker_port_min":49152,"broker_port_max":65535}"#,
                |e| {
                    matches!(
                        e,
                        PfHelperPolicyError::InvalidCidr {
                            field: "ipv6_pool",
                            ..
                        }
                    )
                },
            ),
            (
                r#"{"version":1,"ipv4_pool":"8.8.0.0/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":49152,"broker_port_max":65535}"#,
                |e| matches!(e, PfHelperPolicyError::Invalid { .. }),
            ),
            (
                r#"{"version":1,"ipv4_pool":"10.200.0.0/16","ipv6_pool":"fd00:7772:6974::/48","broker_port_min":65535,"broker_port_max":49152}"#,
                |e| matches!(e, PfHelperPolicyError::Invalid { .. }),
            ),
        ];
        for (contents, is_expected) in cases {
            let path = write_policy(dir.path(), contents, 0o644);
            let err = load_pf_helper_policy(&path, me()).unwrap_err();
            assert!(is_expected(&err), "{contents}: {err}");
        }
    }

    #[test]
    fn a_directory_others_can_write_into_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o775, 0o757, 0o777] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let path = write_policy(dir.path(), &policy().render(), 0o644);
            assert!(
                matches!(
                    load_pf_helper_policy(&path, me()),
                    Err(PfHelperPolicyError::DirectoryWritable { .. })
                ),
                "mode {mode:o}"
            );
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = write_policy(dir.path(), &policy().render(), 0o644);
        assert!(matches!(
            load_pf_helper_policy(&path, me().wrapping_add(1)),
            // The file's owner is checked first, so require the directory's
            // owner check by making the file pass: it cannot, since both are
            // ours. The wrong-owner refusal is the file's.
            Err(PfHelperPolicyError::WrongOwner { .. })
        ));
    }

    proptest! {
        #[test]
        fn parse_inverts_render(policy in arb_policy()) {
            let dir = private_dir();
            let path = write_policy(dir.path(), &policy.render(), 0o600);
            prop_assert_eq!(load_pf_helper_policy(&path, me()).unwrap(), policy);
        }

        /// Whitespace and key order are the operator's; the value is what
        /// counts.
        #[test]
        fn key_order_and_whitespace_are_free(policy in arb_policy(), pad in 0usize..4) {
            let text = format!(
                "{}{{ \"broker_port_max\": {},\n\"ipv6_pool\":\"{}\", \"version\":1,\n \"broker_port_min\":{} ,\"ipv4_pool\" : \"{}\" }}{}",
                " ".repeat(pad),
                policy.broker_port_range().max().get(),
                policy.pool().ipv6_base(),
                policy.broker_port_range().min().get(),
                policy.pool().ipv4_base(),
                "\n".repeat(pad),
            );
            prop_assert_eq!(PfHelperPolicy::parse(Path::new("p"), &text).unwrap(), policy);
        }

        /// A session fact outside the policy's pools or port range is refused
        /// by the same constructors that refused it against the CLI bounds:
        /// install and removal succeed iff the subnet is inside the pool (and
        /// the IPv6 prefix, if any, inside its pool) and every port is inside
        /// the range.
        #[test]
        fn session_facts_are_bounded_by_the_policy(
            (policy, ipv4, ipv6, ports) in arb_policy_and_session_facts(),
        ) {
            let pool = policy.pool();
            let range = policy.broker_port_range();
            let subnet_ok = pool.ipv4_base().contains_subnet(ipv4)
                && ipv6.is_none_or(|v6| pool.ipv6_base().contains_subnet(v6));
            let ports_ok = ports.as_slice().iter().all(|p| range.contains(*p));
            let install = SessionFirewallSpec::new(
                SessionId::new(), pool, ipv4, ipv6, ports.clone(), range, None, None,
            );
            prop_assert_eq!(install.is_ok(), subnet_ok && ports_ok, "{:?}", install.err());
            let removal = SessionFirewallRemoval::new(SessionId::new(), pool, ipv4, ipv6);
            prop_assert_eq!(removal.is_ok(), subnet_ok, "{:?}", removal.err());
        }
    }

    /// The bounding property is only evidence if both verdicts occur; the
    /// generator biases toward in-pool, in-range facts half the time, and this
    /// checks that both an accepted and a refused install actually arise.
    #[test]
    fn the_session_fact_generator_reaches_both_verdicts() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::deterministic();
        let (mut accepted, mut refused) = (0usize, 0usize);
        for _ in 0..1000 {
            let (policy, ipv4, ipv6, ports) = arb_policy_and_session_facts()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            let spec = SessionFirewallSpec::new(
                SessionId::new(),
                policy.pool(),
                ipv4,
                ipv6,
                ports,
                policy.broker_port_range(),
                None,
                None,
            );
            if spec.is_ok() {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
        assert!(accepted >= 100, "accepted {accepted} of 1000");
        assert!(refused >= 100, "refused {refused} of 1000");
    }

    /// A policy and a session's facts: half the time the subnet and every
    /// port are drawn from inside the policy, otherwise from anywhere private.
    #[allow(clippy::type_complexity)]
    fn arb_policy_and_session_facts()
    -> impl Strategy<Value = (PfHelperPolicy, Ipv4Cidr, Option<Ipv6Cidr>, BrokerPorts)> {
        (arb_policy(), any::<bool>(), any::<u16>(), any::<bool>()).prop_flat_map(
            |(policy, inside, index, with_ipv6)| {
                let pool = policy.pool();
                let range = policy.broker_port_range();
                let (min, max) = (range.min().get(), range.max().get());
                let ports = if inside {
                    prop::collection::btree_set(min..=max, 1..4).boxed()
                } else {
                    prop::collection::btree_set(1024u16..=u16::MAX, 1..4).boxed()
                };
                let subnets = if inside {
                    // Any index the pool can allocate, wrapped into range.
                    let capacity = 1u32
                        << (24 - pool.ipv4_base().prefix()).min(64 - pool.ipv6_base().prefix());
                    let network = pool.allocate((u32::from(index) % capacity) as u16).unwrap();
                    Just((network.ipv4(), with_ipv6.then_some(network.ipv6()))).boxed()
                } else {
                    (any::<u16>(), any::<u64>())
                        .prop_map(move |(slot, hi)| {
                            let raw = 0x0A00_0000u32 | (u32::from(slot) << 8);
                            let ipv4 = Ipv4Cidr::new(Ipv4Addr::from(raw), 24).unwrap();
                            let raw6 = (0xfd00u128 << 112)
                                | (u128::from(hi & 0x0000_ffff_ffff_ffff) << 64);
                            let ipv6 = Ipv6Cidr::new(Ipv6Addr::from(raw6), 64).unwrap();
                            (ipv4, with_ipv6.then_some(ipv6))
                        })
                        .boxed()
                };
                (Just(policy), subnets, ports).prop_map(|(policy, (ipv4, ipv6), ports)| {
                    let ports =
                        BrokerPorts::new(ports.into_iter().map(|p| BrokerPort::new(p).unwrap()))
                            .unwrap();
                    (policy, ipv4, ipv6, ports)
                })
            },
        )
    }
}
