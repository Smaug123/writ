//! The locked profile's `container run`, and the readback that proves the
//! running VM is the one the host asked for.
//!
//! Stage E2b of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`. Inert: no
//! session can be in the locked mode until Stage E2c gives
//! [`Ipv6IsolationMode`](crate::agent_vm_lifecycle::Ipv6IsolationMode) a
//! variant for it.
//!
//! # Why a readback and not a digest reference
//!
//! The design asks the locked start to name its image by the digest Stage D
//! inspected, so the image that was admitted is the image that runs. Apple
//! `container` 1.4.1 cannot do that for the guest image: a `name@sha256:…`
//! reference is resolved against the registry (`container run
//! writ-agent-vm-guest@sha256:…` fails with a 401 from `registry-1.docker.io`),
//! and the guest image is built locally and pushed nowhere. A bare digest or
//! image id is refused outright ("cannot specify 64 byte hex string as
//! reference"). Only a tag names a local image.
//!
//! So the guarantee is taken the other way round, the same way Stage C2 takes
//! it for PF: start by tag, then *read back* what actually started and refuse
//! to go on unless it matches. [`LockedContainerShape`] is what
//! `container inspect <vm>` reports about the running VM, and
//! [`LockedContainerShape::verify`] accepts only the admitted digest, exactly
//! the Stage B1 capability set, exactly the intended `/proc` relaxation, and
//! the initializer as PID 1 running as root.
//!
//! This is stronger than the reference would have been. A digest reference
//! says what the host *asked for*; the readback says what the runtime
//! *actually built*, which is also where a flag that was accepted but ignored
//! would show up.
//!
//! The readback must therefore happen **before the container runs**, and that
//! is why the locked launch is `container create` then `container start`
//! rather than `container run`. `create` resolves the tag and records the
//! resolved digest without executing anything, so the verification happens
//! while the container is still `stopped`. Reasoning that a post-`run` window
//! is harmless because PID 1 is the initializer waiting for release would be
//! circular: if the tag were repointed between admission and launch, the
//! replacement image's PID 1 is whatever its author chose, need not wait for
//! anything, and would already be running behind only the bootstrap
//! firewall.
//!
//! # Why `/proc/sys` is writable
//!
//! Apple `container`'s vminit mounts `/proc/bus`, `/proc/fs`, `/proc/irq` and
//! `/proc/sys` read-only. The Stage B1 handoff *must* write
//! `net.ipv6.conf.*.disable_ipv6` — `Ipv6Sysctl::must_exist` makes a missing
//! `disable_ipv6` a handoff failure, because the verification step relies on
//! it — so under the defaults the locked handoff cannot complete. Measured on
//! `container` 1.4.1: the write fails with `EROFS` even holding
//! `CAP_NET_ADMIN`.
//!
//! `--read-only-path` only ever *adds* to the defaults, except for the value
//! `NONE`, which clears them. So the launch clears them and gives back every
//! one except `/proc/sys`, which is the smallest relaxation that lets the
//! handoff run: measured, `/proc/sys` becomes writable and a write to
//! `/proc/irq` is still refused.
//!
//! The relaxation is spent inside the trusted window. PID 1 writes the
//! sysctls, then drops every capability, sets `NoNewPrivs`, and becomes
//! 1000:1000; the workload that follows is unprivileged and the sysctl files
//! are root-owned, so it can no more write them than it could under the
//! default mount. The list of paths to give back is specific to a `container`
//! version, which is safe because Stage D pins the CLI version as a whole
//! record — a runtime that grew a fifth default read-only path would close the
//! profile until the proof was re-run against it.
//!
//! Note the legacy profile's `--kernel-arg ipv6.disable=1` is deliberately
//! *not* used here: it removes `/proc/sys/net/ipv6` entirely, which is exactly
//! the `disable_ipv6` the handoff requires to exist. The locked profile's
//! IPv6 posture is the initializer's writes plus the capability drop that
//! makes them irreversible, with host PF as the backstop either way.

use std::collections::BTreeSet;

use writ_guest_init::capability_argv::TemporaryCapability;

use crate::agent_vm_locked_admission::ImageDigest;

/// Where the official image installs the guest initializer.
///
/// A regular file outside `/nix` and outside `/bin`'s store symlinks, because
/// the handoff chowns the store to the workload; see `flake.nix`. The locked
/// launch names this path as the container command, leaving the image's own
/// entrypoint alone so the legacy profile's launch of the same image is
/// untouched.
pub const GUEST_INIT_PATH: &str = "/sbin/writ-agent-vm-guest-init";

/// The `container` runtime's default read-only paths that the locked launch
/// keeps, i.e. every one except `/proc/sys`.
///
/// Measured against Apple `container` 1.4.1, whose defaults are these three
/// plus `/proc/sys`. See the module docs for why the list is version-specific
/// and why that is safe.
pub const LOCKED_KEPT_READONLY_PATHS: [&str; 3] = ["/proc/bus", "/proc/fs", "/proc/irq"];

/// The `--read-only-path` arguments that relax exactly `/proc/sys`.
///
/// `NONE` first, which clears the runtime defaults, then each path that is
/// given back.
pub fn locked_readonly_path_argv() -> Vec<String> {
    let mut argv = vec!["--read-only-path".to_string(), "NONE".to_string()];
    for path in LOCKED_KEPT_READONLY_PATHS {
        argv.push("--read-only-path".to_string());
        argv.push(path.to_string());
    }
    argv
}

/// How `container inspect` spells a capability: the argv's bare name with a
/// `CAP_` prefix.
///
/// The two spellings are a real difference, not a detail — `--cap-add CHOWN`
/// reads back as `CAP_CHOWN` — so the readback converts rather than comparing
/// the strings it sent.
fn inspect_capability_name(capability: TemporaryCapability) -> String {
    format!("CAP_{}", capability.container_name())
}

/// The capability set [`LockedContainerShape::verify`] requires, as
/// `container inspect` spells it.
fn expected_cap_add() -> BTreeSet<String> {
    TemporaryCapability::ALL
        .into_iter()
        .map(inspect_capability_name)
        .collect()
}

/// What `container inspect <vm>` says the running locked VM actually is.
///
/// Every field is one the launch chose, so every field is one a readback can
/// disagree about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedContainerShape {
    image_digest: ImageDigest,
    image_reference: String,
    cap_add: BTreeSet<String>,
    cap_drop: Vec<String>,
    readonly_paths: BTreeSet<String>,
    init_executable: String,
    init_uid: u32,
    init_gid: u32,
    use_init: bool,
}

/// Why `container inspect` output is not a locked container's shape.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockedShapeParseError {
    #[error("the inspect output is not the document this host reads")]
    Malformed,
    #[error("the inspect output describes {0} containers, not one")]
    NotExactlyOneContainer(usize),
    #[error("the running container's image digest is unreadable: {0}")]
    ImageDigest(#[from] crate::agent_vm_locked_admission::ImageDigestParseError),
}

/// Why the running container is not the one the host asked for.
///
/// Each variant names the field that disagrees and both sides of the
/// disagreement, because an operator reading a refused start needs to know
/// which of the two moved.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockedShapeMismatch {
    #[error("the running VM is image {running}, not the admitted {admitted}")]
    ImageDigest {
        admitted: ImageDigest,
        running: ImageDigest,
    },
    #[error("the running VM holds capabilities {running:?}, not {expected:?}")]
    Capabilities {
        expected: BTreeSet<String>,
        running: BTreeSet<String>,
    },
    #[error("the running VM drops {running:?}, not [\"ALL\"]")]
    CapDrop { running: Vec<String> },
    #[error("the running VM keeps {running:?} read-only, not {expected:?}")]
    ReadonlyPaths {
        expected: BTreeSet<String>,
        running: BTreeSet<String>,
    },
    #[error("the running VM's first process is {running:?}, not {GUEST_INIT_PATH:?}")]
    InitExecutable { running: String },
    #[error("the running VM's first process is {uid}:{gid}, not root")]
    InitIdentity { uid: u32, gid: u32 },
    #[error("the running VM interposes the runtime's own init process as PID 1")]
    RuntimeInitInterposed,
}

impl LockedContainerShape {
    /// Read the document `container inspect <vm>` prints.
    pub fn parse(stdout: &str) -> Result<Self, LockedShapeParseError> {
        let containers: Vec<wire::Container> =
            serde_json::from_str(stdout).map_err(|_| LockedShapeParseError::Malformed)?;
        let [container] = <[wire::Container; 1]>::try_from(containers)
            .map_err(|found| LockedShapeParseError::NotExactlyOneContainer(found.len()))?;
        let configuration = container.configuration;
        Ok(Self {
            image_digest: ImageDigest::parse(&configuration.image.descriptor.digest)?,
            image_reference: configuration.image.reference,
            cap_add: configuration.cap_add.into_iter().collect(),
            cap_drop: configuration.cap_drop,
            readonly_paths: configuration.readonly_paths.into_iter().collect(),
            init_executable: configuration.init_process.executable,
            init_uid: configuration.init_process.user.id.uid,
            init_gid: configuration.init_process.user.id.gid,
            use_init: configuration.use_init,
        })
    }

    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }

    /// What the runtime resolved the tag to, for the operator's benefit. Not
    /// part of [`Self::verify`]: the reference is a name, and the digest is
    /// the identity.
    pub fn image_reference(&self) -> &str {
        &self.image_reference
    }

    /// Accept this running container iff it is the one the locked launch asked
    /// for: the admitted image, exactly Stage B1's capability set over a
    /// dropped-all base, exactly the intended `/proc` relaxation, and the
    /// initializer as a root PID 1.
    ///
    /// Checked in the order a reader would ask them, and the first
    /// disagreement is the one reported — a container running the wrong image
    /// has nothing useful to say about its capabilities.
    pub fn verify(&self, admitted: &ImageDigest) -> Result<(), LockedShapeMismatch> {
        if &self.image_digest != admitted {
            return Err(LockedShapeMismatch::ImageDigest {
                admitted: admitted.clone(),
                running: self.image_digest.clone(),
            });
        }
        if self.cap_drop != ["ALL"] {
            return Err(LockedShapeMismatch::CapDrop {
                running: self.cap_drop.clone(),
            });
        }
        let expected = expected_cap_add();
        if self.cap_add != expected {
            return Err(LockedShapeMismatch::Capabilities {
                expected,
                running: self.cap_add.clone(),
            });
        }
        let expected: BTreeSet<String> = LOCKED_KEPT_READONLY_PATHS
            .into_iter()
            .map(str::to_string)
            .collect();
        if self.readonly_paths != expected {
            return Err(LockedShapeMismatch::ReadonlyPaths {
                expected,
                running: self.readonly_paths.clone(),
            });
        }
        // `useInit` makes the runtime's own signal-forwarding init PID 1 and
        // the configured executable its *child*, so every claim below about
        // "PID 1" would be about the wrong process — including the release
        // gate's later read of `/proc/1/status`, and the `USR1` the runtime
        // would be free to handle itself rather than deliver.
        if self.use_init {
            return Err(LockedShapeMismatch::RuntimeInitInterposed);
        }
        if self.init_executable != GUEST_INIT_PATH {
            return Err(LockedShapeMismatch::InitExecutable {
                running: self.init_executable.clone(),
            });
        }
        // PID 1 must start as root: the handoff chowns directories and changes
        // identity, and both need the authority it gives up on the way out.
        // The locked identity is what PID 1 *becomes*, never what it starts
        // as — a container started as 1000:1000 outright could hand nothing
        // over, and would reach `security-ready` having proved nothing.
        if self.init_uid != 0 || self.init_gid != 0 {
            return Err(LockedShapeMismatch::InitIdentity {
                uid: self.init_uid,
                gid: self.init_gid,
            });
        }
        Ok(())
    }
}

/// The subset of `container inspect`'s document this host reads.
mod wire {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(super) struct Container {
        pub(super) configuration: Configuration,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct Configuration {
        pub(super) image: Image,
        #[serde(default)]
        pub(super) cap_add: Vec<String>,
        #[serde(default)]
        pub(super) cap_drop: Vec<String>,
        #[serde(default)]
        pub(super) readonly_paths: Vec<String>,
        pub(super) init_process: InitProcess,
        /// Absent is the runtime's default, which is "no interposed init".
        #[serde(default)]
        pub(super) use_init: bool,
    }

    #[derive(Deserialize)]
    pub(super) struct Image {
        pub(super) descriptor: Descriptor,
        #[serde(default)]
        pub(super) reference: String,
    }

    #[derive(Deserialize)]
    pub(super) struct Descriptor {
        pub(super) digest: String,
    }

    #[derive(Deserialize)]
    pub(super) struct InitProcess {
        pub(super) executable: String,
        pub(super) user: User,
    }

    #[derive(Deserialize)]
    pub(super) struct User {
        pub(super) id: UserId,
    }

    #[derive(Deserialize)]
    pub(super) struct UserId {
        pub(super) uid: u32,
        pub(super) gid: u32,
    }
}

#[cfg(test)]
mod tests;
