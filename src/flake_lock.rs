//! Lock-driven functional core for flake-input provisioning.
//!
//! The broker provisions a repo's *committed, locked* flake inputs into a
//! binary cache the no-egress guest can substitute from (see the
//! flake-input-provisioning plan). Before shelling out to `nix flake
//! archive`, this module parses `flake.lock`, enumerates the transitive
//! input graph, and decides — purely, from the lock alone — whether the
//! provisioning is admissible:
//!
//!   * the lock must be present and a supported version (parse, don't
//!     validate: a stale or missing lock is the caller's to handle, but a
//!     malformed one fails closed here);
//!   * the input count must be within the configured bound (a hostile or
//!     pathological lock cannot make the host fetch unboundedly many
//!     sources); and
//!   * every input must be a *public network source*. v1 brokers only
//!     public inputs, so an input whose locked source statically requires
//!     credentials (an `ssh`/`git+ssh` transport, or a URL with embedded
//!     userinfo) is rejected with a clear message rather than handed to a
//!     fetch that would either prompt or leak; and a *local-filesystem*
//!     source — a `path` input or a `file://` URL — is rejected too,
//!     because the lock comes from an untrusted repo and could name a
//!     broker-local path (`/etc/...`, `~/.ssh/...`) that `nix flake
//!     archive` would copy into the cache the guest substitutes from.
//!
//! Whether a `github:`/`https:` input is *actually* public cannot be known
//! from the lock — a private GitHub repo locks identically to a public one.
//! Those are admitted here and fail (clearly) at the fetch if they turn out
//! to need credentials; this core rejects only what is *statically*
//! auth-requiring. The output is a [`FlakeProvisionPlan`]: an inert
//! description of the `nix flake archive` invocation for the edge to run.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// Lock-format versions whose `nodes` graph this module understands. Nix
/// has used the v5–v7 shape (the node map keyed by id, each non-root node
/// carrying `locked`/`original`) for years; a version outside this set is
/// rejected rather than parsed on a guess.
const SUPPORTED_LOCK_VERSIONS: &[u64] = &[5, 6, 7];

/// A parsed, structurally-valid `flake.lock`: its version and the classified
/// transitive input graph (every node except the root).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeLock {
    version: u64,
    inputs: Vec<FlakeLockInput>,
}

/// One node of the input graph, identified by its key in the lock's `nodes`
/// map, carrying how its locked source would be fetched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeLockInput {
    node_id: String,
    class: FlakeInputClass,
}

/// How an input's *locked* source is fetched, classified for brokerability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlakeInputClass {
    /// Fetchable from a public network source without credentials: a public
    /// forge shorthand (`github`/`gitlab`/`sourcehut`) or an `http(s)` URL
    /// with no embedded userinfo.
    Public { source_type: String },
    /// Statically needs credentials: an `ssh`/`git+ssh` transport or a URL
    /// carrying embedded `user[:pass]@` userinfo.
    RequiresCredentials { reason: String },
    /// A source this version does not provision: a local-filesystem source (a
    /// `path` input or a `file://` URL, which an untrusted lock could point at
    /// broker-local files to copy into the guest-visible cache), an unresolved
    /// `indirect` registry reference, an unknown type, or a URL input with no
    /// URL.
    Unsupported { reason: String },
}

/// Bounds enforced fail-closed on a provisioning run. `max_input_count` is
/// enforced here in the functional core (from the lock); `max_total_bytes`
/// and `timeout` are enforced at the edge that runs `nix`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FlakeProvisionBounds {
    max_input_count: usize,
    max_total_bytes: u64,
    timeout: Duration,
}

/// An inert description of the `nix flake archive` invocation that provisions
/// a flake's locked inputs into a broker-local binary cache. Built only from
/// an already-validated lock and absolute paths, so constructing one is the
/// pre-flight gate: if `new` returns `Ok`, the run is admissible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeProvisionPlan {
    nix_program: PathBuf,
    flake_dir: PathBuf,
    cache_dir: PathBuf,
    input_count: usize,
    bounds: FlakeProvisionBounds,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FlakeLockError {
    #[error("flake.lock is empty; v1 requires a committed flake.lock")]
    Empty,
    #[error("flake.lock is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("flake.lock has no `version`")]
    MissingVersion,
    #[error("flake.lock version {0} is unsupported (expected one of 5, 6, 7)")]
    UnsupportedVersion(u64),
    #[error("flake.lock has no `nodes`")]
    MissingNodes,
    #[error("flake.lock has no `root`")]
    MissingRoot,
    #[error("flake.lock `root` references node {0:?} which is not in `nodes`")]
    RootNotFound(String),
    #[error("flake.lock input node {node:?} is malformed: {reason}")]
    InvalidNode { node: String, reason: String },
    #[error(
        "flake.lock declares {count} inputs, exceeding the configured maximum of {max}; \
         provisioning fails closed rather than fetch an unbounded input graph"
    )]
    TooManyInputs { count: usize, max: usize },
    #[error("flake.lock input {node:?} requires credentials to fetch: {reason}")]
    InputRequiresCredentials { node: String, reason: String },
    #[error("flake.lock input {node:?} cannot be provisioned: {reason}")]
    UnsupportedInput { node: String, reason: String },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FlakeProvisionBoundsError {
    #[error("maximum flake input count must be greater than zero")]
    EmptyMaxInputCount,
    #[error("maximum flake provision total bytes must be greater than zero")]
    EmptyMaxTotalBytes,
    #[error("flake provision timeout must be greater than zero")]
    EmptyTimeout,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FlakeProvisionPlanError {
    #[error("flake directory must be an absolute path: {0}")]
    RelativeFlakeDir(PathBuf),
    #[error("provisioning cache directory must be an absolute path: {0}")]
    RelativeCacheDir(PathBuf),
    #[error(transparent)]
    Lock(#[from] FlakeLockError),
}

/// Raw `flake.lock` shape for deserialisation. Every field is optional so a
/// truncated or hostile document yields a precise [`FlakeLockError`] from the
/// validation below rather than a generic serde "missing field".
#[derive(Deserialize)]
struct RawLock {
    version: Option<u64>,
    root: Option<String>,
    nodes: Option<HashMap<String, RawNode>>,
}

#[derive(Deserialize)]
struct RawNode {
    #[serde(default)]
    locked: Option<RawLocked>,
}

#[derive(Deserialize)]
struct RawLocked {
    #[serde(rename = "type")]
    source_type: Option<String>,
    url: Option<String>,
    /// Content pin: present on every genuinely-locked node. An admitted input
    /// must carry it, or "provisioning the committed lock" would fetch
    /// unpinned, moving content.
    #[serde(rename = "narHash")]
    nar_hash: Option<String>,
    /// Revision pin for the forge/VCS source types (github/gitlab/sourcehut,
    /// git, mercurial).
    rev: Option<String>,
    /// Self-hosted forge host override (e.g. a private GitHub Enterprise). If
    /// set, it is the network host the fetch hits, so it is SSRF-checked.
    host: Option<String>,
}

impl FlakeLock {
    /// Parse and structurally validate `flake.lock` bytes, classifying every
    /// input by how its locked source is fetched. Does *not* apply bounds or
    /// the public-only policy — that is [`FlakeProvisionPlan::new`], so the
    /// "what the lock says" and "is it admissible" concerns stay separate.
    pub fn parse(bytes: &[u8]) -> Result<Self, FlakeLockError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(FlakeLockError::Empty);
        }
        let raw: RawLock = serde_json::from_slice(bytes)
            .map_err(|err| FlakeLockError::InvalidJson(err.to_string()))?;

        let version = raw.version.ok_or(FlakeLockError::MissingVersion)?;
        if !SUPPORTED_LOCK_VERSIONS.contains(&version) {
            return Err(FlakeLockError::UnsupportedVersion(version));
        }
        let nodes = raw.nodes.ok_or(FlakeLockError::MissingNodes)?;
        let root = raw.root.ok_or(FlakeLockError::MissingRoot)?;
        if !nodes.contains_key(&root) {
            return Err(FlakeLockError::RootNotFound(root));
        }

        // Enumerate the transitive input graph: every node except the root.
        // Sort by node id so the classification (and any error) is
        // deterministic regardless of the JSON map's iteration order.
        let mut node_ids: Vec<&String> = nodes.keys().filter(|id| **id != root).collect();
        node_ids.sort();

        let mut inputs = Vec::with_capacity(node_ids.len());
        for node_id in node_ids {
            let node = &nodes[node_id];
            let locked = node
                .locked
                .as_ref()
                .ok_or_else(|| FlakeLockError::InvalidNode {
                    node: node_id.clone(),
                    reason: "non-root node has no `locked` source".to_string(),
                })?;
            let class = classify_locked(node_id, locked)?;
            inputs.push(FlakeLockInput {
                node_id: node_id.clone(),
                class,
            });
        }

        Ok(Self { version, inputs })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn inputs(&self) -> &[FlakeLockInput] {
        &self.inputs
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Check the lock against a bound and the public-only policy, returning
    /// the first offending input as a clear error. Used by
    /// [`FlakeProvisionPlan::new`]; exposed for callers that want the gate
    /// without building a plan.
    pub fn check_provisionable(&self, max_input_count: usize) -> Result<(), FlakeLockError> {
        let count = self.inputs.len();
        if count > max_input_count {
            return Err(FlakeLockError::TooManyInputs {
                count,
                max: max_input_count,
            });
        }
        for input in &self.inputs {
            match &input.class {
                FlakeInputClass::Public { .. } => {}
                FlakeInputClass::RequiresCredentials { reason } => {
                    return Err(FlakeLockError::InputRequiresCredentials {
                        node: input.node_id.clone(),
                        reason: reason.clone(),
                    });
                }
                FlakeInputClass::Unsupported { reason } => {
                    return Err(FlakeLockError::UnsupportedInput {
                        node: input.node_id.clone(),
                        reason: reason.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl FlakeLockInput {
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn class(&self) -> &FlakeInputClass {
        &self.class
    }
}

fn classify_locked(node_id: &str, locked: &RawLocked) -> Result<FlakeInputClass, FlakeLockError> {
    let Some(source_type) = locked.source_type.as_deref() else {
        return Err(FlakeLockError::InvalidNode {
            node: node_id.to_string(),
            reason: "locked source has no `type`".to_string(),
        });
    };
    let class = match source_type {
        // Public forge shorthands fetch credential-free for public repos.
        // A private repo locks identically; that surfaces at the fetch, not
        // here (see the module docs). Require the rev + narHash content pins
        // so an unpinned (stale/hostile) node cannot pass as a locked input,
        // and SSRF-check any self-hosted `host` override.
        "github" | "gitlab" | "sourcehut" => {
            if let Some(reason) = unpinned_reason(node_id, source_type, locked, true) {
                FlakeInputClass::Unsupported { reason }
            } else if let Some(host) = locked.host.as_deref()
                && disallowed_url_host("https", host)
            {
                FlakeInputClass::Unsupported {
                    reason: format!(
                        "{source_type:?} input {node_id:?} targets a broker-local/internal \
                         host {host:?}; only public hosts are provisioned"
                    ),
                }
            } else {
                FlakeInputClass::Public {
                    source_type: source_type.to_string(),
                }
            }
        }
        // Local filesystem source. It needs no network, but the lock comes
        // from an untrusted repo and could name a broker-local path; archiving
        // it would copy broker files into the cache the guest substitutes
        // from. v1 provisions only public network inputs, so reject it.
        "path" => FlakeInputClass::Unsupported {
            reason: format!(
                "local `path` input {node_id:?} is not provisioned in v1 \
                 (a host-local path could copy broker files into the guest-visible cache)"
            ),
        },
        // URL-bearing fetchers: brokerable only over a credential-free
        // transport, when locked, to a public host.
        "tarball" | "file" | "git" | "mercurial" => {
            classify_url_source(node_id, source_type, locked)
        }
        // A locked graph should have no unresolved registry indirection.
        "indirect" => FlakeInputClass::Unsupported {
            reason: format!("input {node_id:?} is an unresolved registry (`indirect`) reference"),
        },
        other => FlakeInputClass::Unsupported {
            reason: format!("input {node_id:?} has unsupported source type {other:?}"),
        },
    };
    Ok(class)
}

/// `Some(reason)` if `locked` lacks the content pins that make it a genuinely
/// locked node: every admitted type needs a `narHash`, and VCS types
/// (`requires_rev`) need a `rev` too. Provisioning an unpinned node would
/// fetch moving content, breaking the locked-input guarantee.
fn unpinned_reason(
    node_id: &str,
    source_type: &str,
    locked: &RawLocked,
    requires_rev: bool,
) -> Option<String> {
    if !pin_present(&locked.nar_hash) {
        return Some(format!(
            "{source_type:?} input {node_id:?} is not locked: it has no `narHash` content pin"
        ));
    }
    if requires_rev && !pin_present(&locked.rev) {
        return Some(format!(
            "{source_type:?} input {node_id:?} is not locked: it has no `rev` pin"
        ));
    }
    None
}

fn pin_present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|value| !value.is_empty())
}

fn classify_url_source(node_id: &str, source_type: &str, locked: &RawLocked) -> FlakeInputClass {
    // git/mercurial pin a `rev`; tarball/file are content-addressed by
    // `narHash` alone.
    let requires_rev = matches!(source_type, "git" | "mercurial");
    if let Some(reason) = unpinned_reason(node_id, source_type, locked, requires_rev) {
        return FlakeInputClass::Unsupported { reason };
    }
    let Some(url) = locked.url.as_deref() else {
        return FlakeInputClass::Unsupported {
            reason: format!("{source_type:?} input {node_id:?} has no `url`"),
        };
    };
    let Some((scheme, rest)) = url.split_once("://") else {
        return FlakeInputClass::Unsupported {
            reason: format!(
                "{source_type:?} input {node_id:?} has a url without a scheme: {url:?}"
            ),
        };
    };
    // `git+ssh`, `hg+https`, … — the transport is the part after the last
    // `+`; `https`/`http`/`ssh`/`file` are their own transport.
    let transport = scheme.rsplit('+').next().unwrap_or(scheme);
    // Userinfo (`user[:pass]@host`) sits before the first `/`, `?`, or `#` of
    // the part after `://`. Its presence means the lock carries credentials.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let has_userinfo = authority.contains('@');

    match transport {
        "https" | "http" if has_userinfo => FlakeInputClass::RequiresCredentials {
            reason: format!("{source_type:?} input {node_id:?} url embeds credentials: {url:?}"),
        },
        "https" | "http" => {
            // SSRF guard: the host must not be loopback, link-local (incl. the
            // 169.254.169.254 cloud-metadata endpoint), private, or localhost —
            // an untrusted lock must not steer the host-side fetch at
            // broker-internal services. Re-serialise with the bare transport so
            // the url crate's WHATWG special-host parser canonicalises the host
            // the way libcurl/Nix do, closing decimal/hex/octal integer IPv4
            // aliases and query/fragment-smuggling bypasses.
            if disallowed_url_host(transport, rest) {
                FlakeInputClass::Unsupported {
                    reason: format!(
                        "{source_type:?} input {node_id:?} targets a broker-local/internal \
                         host: {url:?}; only public hosts are provisioned"
                    ),
                }
            } else {
                FlakeInputClass::Public {
                    source_type: source_type.to_string(),
                }
            }
        }
        // A local `file://` source, like a `path` input, could copy
        // broker-local files into the guest-visible cache. Reject it.
        "file" => FlakeInputClass::Unsupported {
            reason: format!(
                "{source_type:?} input {node_id:?} has a local `file://` url {url:?}; v1 does not \
                 provision local-filesystem inputs (they could copy broker files into the \
                 guest-visible cache)"
            ),
        },
        "ssh" => FlakeInputClass::RequiresCredentials {
            reason: format!("{source_type:?} input {node_id:?} uses an ssh transport: {url:?}"),
        },
        other => FlakeInputClass::Unsupported {
            reason: format!(
                "{source_type:?} input {node_id:?} uses unsupported transport {other:?}: {url:?}"
            ),
        },
    }
}

/// True if the host in `{scheme}://{rest}` is one an untrusted lock must not
/// steer a host-side fetch at. `rest` is everything after `://`; re-serialising
/// with the bare `scheme` (`http`/`https`) lets the url crate apply WHATWG
/// special-host canonicalisation — the same normalisation libcurl/Nix do — so
/// integer/hex/octal IPv4 aliases (`2130706433`, `0x7f000001`) and
/// query/fragment-smuggled authorities resolve to their real host before the
/// range check. A parse failure or hostless URL fails closed.
fn disallowed_url_host(scheme: &str, rest: &str) -> bool {
    match reqwest::Url::parse(&format!("{scheme}://{rest}")) {
        Ok(url) => url.host_str().is_none_or(is_disallowed_host),
        Err(_) => true,
    }
}

/// True if `host` (already canonicalised by the url crate) is one we refuse:
/// `localhost`, or an IP literal that is loopback, link-local (incl. the
/// 169.254.169.254 cloud-metadata endpoint), private, shared (CGNAT),
/// unspecified, or broadcast. A domain name is allowed — it cannot be resolved
/// here without a network call, and DNS-rebinding defence belongs at the fetch,
/// not in static lock classification.
fn is_disallowed_host(host: &str) -> bool {
    // A fully-qualified name may carry trailing dots (`localhost.`), which the
    // url crate preserves; strip them so the localhost check below — and the IP
    // parse — cannot be bypassed by an absolute-form name.
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => is_disallowed_ip(ip),
        Err(_) => false,
    }
}

fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || is_shared_cgnat_v4(v4)
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_ip(std::net::IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || is_link_local_v6(v6)
                || is_unique_local_v6(v6)
        }
    }
}

/// 100.64.0.0/10 — the carrier-grade-NAT shared range, not a public host.
fn is_shared_cgnat_v4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    a == 100 && (64..=127).contains(&b)
}

/// fe80::/10 — IPv6 link-local. (`Ipv6Addr::is_unicast_link_local` is unstable.)
fn is_link_local_v6(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7 — IPv6 unique-local. (`Ipv6Addr::is_unique_local` is unstable.)
fn is_unique_local_v6(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

impl FlakeProvisionBounds {
    pub fn new(
        max_input_count: usize,
        max_total_bytes: u64,
        timeout: Duration,
    ) -> Result<Self, FlakeProvisionBoundsError> {
        if max_input_count == 0 {
            return Err(FlakeProvisionBoundsError::EmptyMaxInputCount);
        }
        if max_total_bytes == 0 {
            return Err(FlakeProvisionBoundsError::EmptyMaxTotalBytes);
        }
        if timeout.is_zero() {
            return Err(FlakeProvisionBoundsError::EmptyTimeout);
        }
        Ok(Self {
            max_input_count,
            max_total_bytes,
            timeout,
        })
    }

    pub fn max_input_count(&self) -> usize {
        self.max_input_count
    }

    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl FlakeProvisionPlan {
    /// Build the provisioning plan, gating on absolute paths and the lock's
    /// admissibility (bound + public-only). An `Ok` result is the proof that
    /// the run may proceed.
    pub fn new(
        nix_program: PathBuf,
        flake_dir: PathBuf,
        cache_dir: PathBuf,
        bounds: FlakeProvisionBounds,
        lock: &FlakeLock,
    ) -> Result<Self, FlakeProvisionPlanError> {
        if !flake_dir.is_absolute() {
            return Err(FlakeProvisionPlanError::RelativeFlakeDir(flake_dir));
        }
        if !cache_dir.is_absolute() {
            return Err(FlakeProvisionPlanError::RelativeCacheDir(cache_dir));
        }
        lock.check_provisionable(bounds.max_input_count())?;
        Ok(Self {
            nix_program,
            flake_dir,
            cache_dir,
            input_count: lock.input_count(),
            bounds,
        })
    }

    pub fn nix_program(&self) -> &Path {
        &self.nix_program
    }

    pub fn flake_dir(&self) -> &Path {
        &self.flake_dir
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn input_count(&self) -> usize {
        self.input_count
    }

    pub fn bounds(&self) -> FlakeProvisionBounds {
        self.bounds
    }

    /// The `file://` substituter URL of the final cache (the published
    /// destination the guest substitutes from).
    pub fn cache_file_url(&self) -> String {
        file_url(&self.cache_dir)
    }

    /// The argv (excluding the program) for `nix flake archive`, targeting
    /// `archive_to` via `--to`.
    ///
    /// The target is a parameter rather than `cache_dir` so the edge can
    /// archive into a staging directory and publish atomically into the final
    /// `cache_dir` only after the run is verified and audited — `nix` must
    /// never write straight into the guest-visible cache.
    ///
    /// `--no-update-lock-file` is load-bearing: with it, a `flake.nix` and
    /// `flake.lock` that disagree fail closed instead of letting Nix resolve
    /// and archive an *updated* lock graph in memory — provisioning inputs
    /// that are not in the committed, reviewed lock. The experimental-feature
    /// flags make the command work on a host whose `nix.conf` has not opted
    /// into flakes; `allow-import-from-derivation=false` keeps input
    /// discovery from triggering a build on hostile input.
    pub fn nix_archive_args(&self, archive_to: &Path) -> Vec<OsString> {
        vec![
            OsString::from("--extra-experimental-features"),
            OsString::from("nix-command"),
            OsString::from("--extra-experimental-features"),
            OsString::from("flakes"),
            OsString::from("--option"),
            OsString::from("allow-import-from-derivation"),
            OsString::from("false"),
            OsString::from("flake"),
            OsString::from("archive"),
            OsString::from("--to"),
            OsString::from(file_url(archive_to)),
            OsString::from("--no-update-lock-file"),
            self.flake_dir.as_os_str().to_os_string(),
        ]
    }
}

/// Build a `file://` URL for an absolute path, percent-encoding spaces and
/// other URL-reserved characters via the url crate's file-URL serialiser —
/// `format!("file://{path}")` produces an unparseable `--to` store URL for a
/// path like `…/Application Support/…`. Falls back to the raw form only if the
/// path is not absolute (which the plan's constructor already rejects).
fn file_url(path: &Path) -> String {
    reqwest::Url::from_file_path(path)
        .map(|url| url.to_string())
        .unwrap_or_else(|()| format!("file://{}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    fn bounds(max_input_count: usize) -> FlakeProvisionBounds {
        FlakeProvisionBounds::new(max_input_count, 1 << 30, Duration::from_secs(300)).unwrap()
    }

    /// Build a minimal flake.lock JSON from `(node_id, locked_json)` inputs:
    /// a `root` node listing them and one node per input.
    fn lock_json(version: u64, inputs: &[(&str, Value)]) -> Value {
        let mut nodes = serde_json::Map::new();
        let mut root_inputs = serde_json::Map::new();
        for (id, locked) in inputs {
            root_inputs.insert((*id).to_string(), Value::String((*id).to_string()));
            nodes.insert((*id).to_string(), json!({ "locked": locked }));
        }
        nodes.insert("root".to_string(), json!({ "inputs": root_inputs }));
        json!({ "version": version, "root": "root", "nodes": nodes })
    }

    const REV: &str = "0000000000000000000000000000000000000000";
    const NAR_HASH: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn github_locked(owner: &str, repo: &str) -> Value {
        json!({
            "type": "github",
            "owner": owner,
            "repo": repo,
            "rev": REV,
            "narHash": NAR_HASH,
        })
    }

    /// A fully-pinned `git` locked node, so the test reaches transport/host
    /// classification rather than the not-locked gate.
    fn git_locked(url: &str) -> Value {
        json!({ "type": "git", "url": url, "rev": REV, "narHash": NAR_HASH })
    }

    /// A fully-pinned `tarball` locked node (content-addressed by narHash, no
    /// rev).
    fn tarball_locked(url: &str) -> Value {
        json!({ "type": "tarball", "url": url, "narHash": NAR_HASH })
    }

    fn parse_json(value: &Value) -> Result<FlakeLock, FlakeLockError> {
        FlakeLock::parse(serde_json::to_vec(value).unwrap().as_slice())
    }

    #[test]
    fn parses_the_repos_own_lock_shape_and_counts_inputs() {
        let value = lock_json(
            7,
            &[
                ("flake-utils", github_locked("numtide", "flake-utils")),
                ("nixpkgs", github_locked("NixOS", "nixpkgs")),
                ("systems", github_locked("nix-systems", "default")),
            ],
        );
        let lock = parse_json(&value).unwrap();
        assert_eq!(lock.version(), 7);
        assert_eq!(lock.input_count(), 3);
        for input in lock.inputs() {
            assert!(
                matches!(input.class(), FlakeInputClass::Public { .. }),
                "github input {} should be public, got {:?}",
                input.node_id(),
                input.class()
            );
        }
        lock.check_provisionable(8).unwrap();
    }

    #[test]
    fn empty_or_whitespace_lock_is_rejected() {
        assert_eq!(FlakeLock::parse(b"").unwrap_err(), FlakeLockError::Empty);
        assert_eq!(
            FlakeLock::parse(b"   \n\t  ").unwrap_err(),
            FlakeLockError::Empty
        );
    }

    #[test]
    fn malformed_or_incomplete_locks_are_rejected() {
        assert!(matches!(
            FlakeLock::parse(b"{not json").unwrap_err(),
            FlakeLockError::InvalidJson(_)
        ));
        assert_eq!(
            parse_json(&json!({ "root": "root", "nodes": {} })).unwrap_err(),
            FlakeLockError::MissingVersion
        );
        assert_eq!(
            parse_json(&json!({ "version": 4, "root": "root", "nodes": {} })).unwrap_err(),
            FlakeLockError::UnsupportedVersion(4)
        );
        assert_eq!(
            parse_json(&json!({ "version": 7, "root": "root" })).unwrap_err(),
            FlakeLockError::MissingNodes
        );
        assert_eq!(
            parse_json(&json!({ "version": 7, "nodes": {} })).unwrap_err(),
            FlakeLockError::MissingRoot
        );
        assert_eq!(
            parse_json(&json!({ "version": 7, "root": "root", "nodes": {} })).unwrap_err(),
            FlakeLockError::RootNotFound("root".to_string()),
        );
    }

    #[test]
    fn non_root_node_without_locked_is_rejected() {
        let value = json!({
            "version": 7,
            "root": "root",
            "nodes": {
                "root": { "inputs": { "dep": "dep" } },
                "dep": { "inputs": {} },
            },
        });
        assert!(matches!(
            parse_json(&value).unwrap_err(),
            FlakeLockError::InvalidNode { node, .. } if node == "dep"
        ));
    }

    #[test]
    fn ssh_and_embedded_credential_inputs_require_credentials() {
        let ssh = lock_json(
            7,
            &[(
                "private",
                git_locked("git+ssh://git@github.com/acme/secret"),
            )],
        );
        let lock = parse_json(&ssh).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::InputRequiresCredentials { node, .. } if node == "private"
        ));

        let userinfo = lock_json(
            7,
            &[(
                "private",
                tarball_locked("https://user:pass@host.example/a.tar.gz"),
            )],
        );
        let lock = parse_json(&userinfo).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::InputRequiresCredentials { node, .. } if node == "private"
        ));
    }

    #[test]
    fn http_git_and_tarball_inputs_are_public() {
        let value = lock_json(
            7,
            &[
                ("g", git_locked("https://example.com/acme/pub.git")),
                ("t", tarball_locked("https://example.com/a.tar.gz")),
            ],
        );
        let lock = parse_json(&value).unwrap();
        assert_eq!(lock.input_count(), 2);
        lock.check_provisionable(8).unwrap();
    }

    #[test]
    fn unpinned_inputs_are_rejected() {
        // "Provisioning the committed lock" must mean provisioning *pinned*
        // content. A node missing its narHash (or rev, for VCS types) is not
        // actually locked and must not pass the gate.
        for (label, locked) in [
            (
                "github-no-pins",
                json!({ "type": "github", "owner": "o", "repo": "r" }),
            ),
            (
                "github-no-narhash",
                json!({ "type": "github", "owner": "o", "repo": "r", "rev": REV }),
            ),
            (
                "tarball-no-narhash",
                json!({ "type": "tarball", "url": "https://example.com/a.tar.gz" }),
            ),
            (
                "git-no-rev",
                json!({ "type": "git", "url": "https://example.com/a.git", "narHash": NAR_HASH }),
            ),
        ] {
            let lock = parse_json(&lock_json(7, &[("dep", locked)])).unwrap();
            assert!(
                matches!(
                    lock.check_provisionable(8).unwrap_err(),
                    FlakeLockError::UnsupportedInput { node, .. } if node == "dep"
                ),
                "expected {label} to be rejected as not locked"
            );
        }
    }

    #[test]
    fn internal_and_loopback_http_hosts_are_rejected() {
        // An untrusted lock must not steer the host-side fetch at broker-local
        // or internal services (incl. the cloud-metadata endpoint).
        for host_url in [
            "http://127.0.0.1/x",
            "https://localhost/x",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/x",
            "https://192.168.1.1/x",
            "http://172.16.0.1/x",
            "http://100.64.0.1/x",
            "http://[::1]/x",
            "http://[fe80::1]/x",
            "http://[fd00::1]/x",
            // Authority terminated by query/fragment, not `/`.
            "http://169.254.169.254?x=1",
            "http://127.0.0.1#frag",
            // libcurl-accepted IPv4 aliases the url crate canonicalises to
            // loopback/internal before the range check.
            "http://2130706433/x",
            "http://0x7f000001/x",
            "http://0177.0.0.1/x",
            "http://127.1/x",
            // git+https carries the same canonicalisation path.
            "git+https://127.0.0.1/x",
            // Absolute (trailing-dot) localhost names still resolve to loopback.
            "https://localhost./x",
            "https://foo.localhost./x",
            "https://127.0.0.1./x",
        ] {
            let lock = parse_json(&lock_json(7, &[("dep", tarball_locked(host_url))])).unwrap();
            assert!(
                matches!(
                    lock.check_provisionable(8).unwrap_err(),
                    FlakeLockError::UnsupportedInput { node, .. } if node == "dep"
                ),
                "expected internal host {host_url} to be rejected"
            );
        }

        // Public hosts (a domain and a public IP literal) still pass.
        for host_url in ["https://example.com/x", "https://8.8.8.8/x"] {
            let lock = parse_json(&lock_json(7, &[("dep", tarball_locked(host_url))])).unwrap();
            lock.check_provisionable(8)
                .unwrap_or_else(|err| panic!("expected {host_url} to be public, got {err:?}"));
        }
    }

    #[test]
    fn self_hosted_forge_on_internal_host_is_rejected() {
        let value = lock_json(
            7,
            &[(
                "ghe",
                json!({
                    "type": "github",
                    "owner": "o",
                    "repo": "r",
                    "rev": REV,
                    "narHash": NAR_HASH,
                    "host": "10.0.0.5",
                }),
            )],
        );
        let lock = parse_json(&value).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "ghe"
        ));
    }

    #[test]
    fn local_path_and_file_inputs_are_rejected() {
        // The lock comes from an untrusted repo; a local source named in it
        // must not be archived, or the host's `nix flake archive` would copy
        // broker-local files into the guest-visible cache. A `file://` URL
        // pointing at a host secret is the motivating case.
        let path = lock_json(
            7,
            &[("p", json!({ "type": "path", "path": "/etc/shadow" }))],
        );
        let lock = parse_json(&path).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "p"
        ));

        let file = lock_json(
            7,
            &[(
                "f",
                json!({ "type": "file", "url": "file:///home/user/.ssh/id_rsa", "narHash": NAR_HASH }),
            )],
        );
        let lock = parse_json(&file).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "f"
        ));
    }

    #[test]
    fn indirect_and_unknown_types_are_unsupported() {
        let indirect = lock_json(7, &[("i", json!({ "type": "indirect", "id": "nixpkgs" }))]);
        let lock = parse_json(&indirect).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "i"
        ));

        let unknown = lock_json(7, &[("x", json!({ "type": "carrier-pigeon" }))]);
        let lock = parse_json(&unknown).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "x"
        ));
    }

    #[test]
    fn url_input_without_url_is_unsupported() {
        // Pinned, so it passes the not-locked gate and reaches the missing-url
        // check.
        let value = lock_json(
            7,
            &[(
                "g",
                json!({ "type": "git", "rev": REV, "narHash": NAR_HASH }),
            )],
        );
        let lock = parse_json(&value).unwrap();
        assert!(matches!(
            lock.check_provisionable(8).unwrap_err(),
            FlakeLockError::UnsupportedInput { node, .. } if node == "g"
        ));
    }

    #[test]
    fn bounds_reject_degenerate_values() {
        assert_eq!(
            FlakeProvisionBounds::new(0, 1, Duration::from_secs(1)).unwrap_err(),
            FlakeProvisionBoundsError::EmptyMaxInputCount
        );
        assert_eq!(
            FlakeProvisionBounds::new(1, 0, Duration::from_secs(1)).unwrap_err(),
            FlakeProvisionBoundsError::EmptyMaxTotalBytes
        );
        assert_eq!(
            FlakeProvisionBounds::new(1, 1, Duration::ZERO).unwrap_err(),
            FlakeProvisionBoundsError::EmptyTimeout
        );
    }

    #[test]
    fn plan_requires_absolute_paths() {
        let lock = parse_json(&lock_json(7, &[("u", github_locked("a", "b"))])).unwrap();
        let abs = PathBuf::from("/abs/flake");
        let cache = PathBuf::from("/abs/cache");
        assert!(matches!(
            FlakeProvisionPlan::new(
                PathBuf::from("nix"),
                PathBuf::from("relative/flake"),
                cache.clone(),
                bounds(8),
                &lock,
            )
            .unwrap_err(),
            FlakeProvisionPlanError::RelativeFlakeDir(_)
        ));
        assert!(matches!(
            FlakeProvisionPlan::new(
                PathBuf::from("nix"),
                abs.clone(),
                PathBuf::from("relative/cache"),
                bounds(8),
                &lock,
            )
            .unwrap_err(),
            FlakeProvisionPlanError::RelativeCacheDir(_)
        ));
    }

    #[test]
    fn plan_argv_pins_no_update_lock_file_cache_url_and_flake_dir() {
        let lock = parse_json(&lock_json(7, &[("u", github_locked("a", "b"))])).unwrap();
        let plan = FlakeProvisionPlan::new(
            PathBuf::from("/usr/bin/nix"),
            PathBuf::from("/work/repo"),
            PathBuf::from("/cache/flake"),
            bounds(8),
            &lock,
        )
        .unwrap();
        assert_eq!(plan.input_count(), 1);
        assert_eq!(plan.cache_file_url(), "file:///cache/flake");
        // `--to` targets the supplied (staging) dir, not the final cache_dir.
        let args: Vec<String> = plan
            .nix_archive_args(Path::new("/stage/dir"))
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "--extra-experimental-features",
                "nix-command",
                "--extra-experimental-features",
                "flakes",
                "--option",
                "allow-import-from-derivation",
                "false",
                "flake",
                "archive",
                "--to",
                "file:///stage/dir",
                "--no-update-lock-file",
                "/work/repo",
            ]
        );
    }

    #[test]
    fn nix_archive_to_url_percent_encodes_spaces() {
        let lock = parse_json(&lock_json(7, &[("u", github_locked("a", "b"))])).unwrap();
        let plan = FlakeProvisionPlan::new(
            PathBuf::from("/usr/bin/nix"),
            PathBuf::from("/work/repo"),
            PathBuf::from("/Users/x/Library/Application Support/cache"),
            bounds(8),
            &lock,
        )
        .unwrap();
        // A space-bearing parent (`Application Support`) must yield a valid,
        // percent-encoded file URL nix can parse — not a raw space.
        assert_eq!(
            plan.cache_file_url(),
            "file:///Users/x/Library/Application%20Support/cache"
        );
        let to = plan
            .nix_archive_args(Path::new("/stage dir/cache"))
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let to_value = &to[to.iter().position(|a| a == "--to").unwrap() + 1];
        assert_eq!(to_value, "file:///stage%20dir/cache");
    }

    // ---- property-based tests ----

    fn node_id_strategy() -> impl Strategy<Value = String> {
        // Exclude the reserved `root` id: `lock_json` would insert it as an
        // input node and then overwrite it with the real root node, dropping
        // one input and making the count properties spuriously fail.
        "[a-z][a-z0-9_-]{0,12}".prop_filter("reserved root node id", |id| id != "root")
    }

    prop_compose! {
        fn public_inputs_strategy(max: usize)(
            ids in prop::collection::hash_set(node_id_strategy(), 1..=max)
        ) -> Vec<(String, Value)> {
            ids.into_iter()
                .map(|id| (id, github_locked("owner", "repo")))
                .collect()
        }
    }

    proptest! {
        // Any all-public lock within bound parses, counts correctly, and is
        // admitted; the same lock with a smaller bound is rejected for count.
        #[test]
        fn all_public_locks_parse_and_respect_the_count_bound(
            inputs in public_inputs_strategy(12)
        ) {
            let count = inputs.len();
            let refs: Vec<(&str, Value)> =
                inputs.iter().map(|(id, v)| (id.as_str(), v.clone())).collect();
            let lock = parse_json(&lock_json(7, &refs)).unwrap();

            prop_assert_eq!(lock.input_count(), count);
            for input in lock.inputs() {
                prop_assert!(
                    matches!(input.class(), FlakeInputClass::Public { .. }),
                    "github input must classify as public"
                );
            }
            prop_assert!(lock.check_provisionable(count).is_ok());

            // A bound one below the true count must fail closed.
            match lock.check_provisionable(count - 1) {
                Err(FlakeLockError::TooManyInputs { count: c, max }) => {
                    prop_assert_eq!(c, count);
                    prop_assert_eq!(max, count - 1);
                }
                other => prop_assert!(false, "expected TooManyInputs, got {:?}", other),
            }
        }

        // A single ssh input anywhere in an otherwise-public graph is always
        // rejected as credential-requiring, regardless of the other inputs.
        #[test]
        fn an_ssh_input_is_always_rejected(
            mut inputs in public_inputs_strategy(8),
        ) {
            inputs.push((
                "sshdep".to_string(),
                git_locked("git+ssh://git@host/acme/x"),
            ));
            let refs: Vec<(&str, Value)> =
                inputs.iter().map(|(id, v)| (id.as_str(), v.clone())).collect();
            let lock = parse_json(&lock_json(7, &refs)).unwrap();
            prop_assert!(
                matches!(
                    lock.check_provisionable(64).unwrap_err(),
                    FlakeLockError::InputRequiresCredentials { node, .. } if node == "sshdep"
                ),
                "ssh input must be rejected as credential-requiring"
            );
        }

        // Parsing is independent of `nodes` map ordering: the input count and
        // per-id classes are stable however serde hands us the keys.
        #[test]
        fn classification_is_order_independent(
            inputs in public_inputs_strategy(10)
        ) {
            let refs: Vec<(&str, Value)> =
                inputs.iter().map(|(id, v)| (id.as_str(), v.clone())).collect();
            let lock = parse_json(&lock_json(7, &refs)).unwrap();
            let mut ids: Vec<&str> = lock.inputs().iter().map(FlakeLockInput::node_id).collect();
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            prop_assert_eq!(&ids, &sorted, "inputs must be sorted by node id");
            ids.dedup();
            prop_assert_eq!(ids.len(), lock.input_count(), "node ids must be unique");
        }

        // The SSRF host predicate must agree with an independent reference over
        // every IPv4 literal: a range bug (e.g. mis-sized CGNAT block) shows up
        // as a disagreement on some random address.
        #[test]
        fn ssrf_v4_predicate_matches_reference(bits in any::<u32>()) {
            let octets = bits.to_be_bytes();
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets));
            let [a, b, _, _] = octets;
            let reference = a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || a == 127
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b))
                || octets == [0, 0, 0, 0]
                || octets == [255, 255, 255, 255];
            prop_assert_eq!(
                is_disallowed_ip(ip),
                reference,
                "SSRF v4 predicate disagrees for {:?}",
                ip
            );
        }
    }
}
