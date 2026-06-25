//! Guest-image attribute and agent-VM workspace bootstrap helpers.
//!
//! Pure mappings so the binary can keep its clap-derive
//! `ValueEnum`s without forcing `clap` into the lib's public API.
//! Bin-side adapters convert the clap-derived enums into the plain
//! [`GuestSystem`]/[`WorkspaceWarmMode`] types this module consumes.

use std::path::PathBuf;

use crate::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, WorkspaceWarmMode};

/// Guest OCI image target system, mirroring the flake's
/// `agent-vm-guest-image-<system>` attribute suffixes. The proof
/// harnesses derive this from `uname -m`; we mirror the same mapping
/// against `std::env::consts::ARCH` so the CLI default lines up with
/// the script behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestSystem {
    Aarch64Linux,
    X86_64Linux,
}

impl GuestSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            GuestSystem::Aarch64Linux => "aarch64-linux",
            GuestSystem::X86_64Linux => "x86_64-linux",
        }
    }
}

/// Pure mapping from `std::env::consts::ARCH` (or equivalent string)
/// to the flake's guest system suffix. Mirrors the proof harness's
/// `default_guest_system` shell helper.
pub fn default_guest_system(arch: &str) -> Result<GuestSystem, Box<dyn std::error::Error>> {
    match arch {
        "aarch64" | "arm64" => Ok(GuestSystem::Aarch64Linux),
        "x86_64" | "amd64" => Ok(GuestSystem::X86_64Linux),
        other => Err(format!(
            "unsupported host architecture for default guest image: {other}; \
             pass --guest-system aarch64-linux|x86_64-linux to override",
        )
        .into()),
    }
}

/// Pure helper picking the flake attribute name for a given variant
/// and guest system. The flake exposes
/// `agent-vm-guest-image-<system>` and
/// `agent-vm-guest-proof-image-<system>`; keeping this in one place
/// means the CLI can never drift from the flake's naming scheme.
pub fn guest_image_attr(proof: bool, guest_system: GuestSystem) -> String {
    let prefix = if proof {
        "agent-vm-guest-proof-image"
    } else {
        "agent-vm-guest-image"
    };
    format!("{prefix}-{}", guest_system.as_str())
}

/// The flake attribute name for the broker VM image (`broker_placement = vm`),
/// mirroring the flake's `broker-vm-image-<system>` outputs. Kept beside
/// [`guest_image_attr`] so the CLI never drifts from the flake's naming.
pub fn broker_image_attr(guest_system: GuestSystem) -> String {
    format!("broker-vm-image-{}", guest_system.as_str())
}

pub fn build_workspace_bootstrap(
    repo: Option<String>,
    destination: Option<PathBuf>,
    warm: Option<WorkspaceWarmMode>,
) -> Result<Option<AgentVmWorkspaceBootstrap>, Box<dyn std::error::Error>> {
    let Some(raw_repo) = repo else {
        if destination.is_some() {
            return Err("--workspace requires --repo".into());
        }
        if warm.is_some() {
            return Err("--warm requires --repo".into());
        }
        return Ok(None);
    };
    build_workspace_bootstrap_from_repo(
        raw_repo,
        destination,
        warm.unwrap_or(WorkspaceWarmMode::DevShell),
    )
    .map(Some)
}

pub fn build_workspace_bootstrap_from_repo(
    raw_repo: String,
    destination: Option<PathBuf>,
    warm: WorkspaceWarmMode,
) -> Result<AgentVmWorkspaceBootstrap, Box<dyn std::error::Error>> {
    if let Some(destination) = destination.as_ref()
        && destination.to_str().is_none()
    {
        return Err("--workspace path must be valid UTF-8".into());
    }
    let repo: GitCloneRepo = raw_repo
        .parse()
        .map_err(|err| format!("invalid GitHub repository {raw_repo:?}: {err}"))?;
    Ok(AgentVmWorkspaceBootstrap {
        repo,
        destination,
        warm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_related_flags_require_repo() {
        assert!(
            build_workspace_bootstrap(None, Some(PathBuf::from("/workspace/repo")), None)
                .unwrap_err()
                .to_string()
                .contains("--workspace requires --repo")
        );
        assert!(
            build_workspace_bootstrap(None, None, Some(WorkspaceWarmMode::Sources))
                .unwrap_err()
                .to_string()
                .contains("--warm requires --repo")
        );
    }

    #[test]
    fn workspace_bootstrap_defaults_to_devshell_warmup_when_repo_is_set() {
        let workspace = build_workspace_bootstrap(Some("owner/repo".into()), None, None)
            .unwrap()
            .unwrap();

        assert_eq!(workspace.repo.to_string(), "owner/repo");
        assert_eq!(workspace.destination, None);
        assert_eq!(workspace.warm, WorkspaceWarmMode::DevShell);
    }

    #[test]
    fn workspace_bootstrap_accepts_explicit_none_warmup() {
        let workspace = build_workspace_bootstrap(
            Some("owner/repo".into()),
            Some(PathBuf::from("/workspace/repo")),
            Some(WorkspaceWarmMode::None),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            workspace.destination,
            Some(PathBuf::from("/workspace/repo"))
        );
        assert_eq!(workspace.warm, WorkspaceWarmMode::None);
    }

    #[test]
    fn agent_run_workspace_uses_requested_repo_destination_and_warmup() {
        let workspace = build_workspace_bootstrap_from_repo(
            "owner/repo".into(),
            Some(PathBuf::from("/workspace/custom")),
            WorkspaceWarmMode::Sources,
        )
        .unwrap();

        assert_eq!(workspace.repo.to_string(), "owner/repo");
        assert_eq!(
            workspace.destination,
            Some(PathBuf::from("/workspace/custom"))
        );
        assert_eq!(workspace.warm, WorkspaceWarmMode::Sources);
    }

    /// The CLI must accept exactly the four host-arch spellings the
    /// proof harness's `default_guest_system` shell helper accepts
    /// (`arm64`/`aarch64`, `x86_64`/`amd64`) and surface a clear error
    /// for anything else. This is the only place the `writ` CLI maps
    /// host arch onto the flake's `agent-vm-guest-image-<system>`
    /// suffix, so it doubles as a regression test for the suffix
    /// names.
    #[test]
    fn default_guest_system_maps_arm_and_x86_aliases() {
        for raw in ["aarch64", "arm64"] {
            assert_eq!(
                default_guest_system(raw).unwrap(),
                GuestSystem::Aarch64Linux,
                "{raw} should map to aarch64-linux",
            );
        }
        for raw in ["x86_64", "amd64"] {
            assert_eq!(
                default_guest_system(raw).unwrap(),
                GuestSystem::X86_64Linux,
                "{raw} should map to x86_64-linux",
            );
        }
    }

    #[test]
    fn default_guest_system_rejects_unknown_arch_with_actionable_message() {
        let err = default_guest_system("riscv64")
            .expect_err("riscv64 has no flake guest image target")
            .to_string();
        assert!(
            err.contains("riscv64"),
            "error should name the bad arch: {err}"
        );
        assert!(
            err.contains("--guest-system"),
            "error should point at the override flag: {err}",
        );
    }

    /// The attribute name is the contract between the CLI and the
    /// flake's `packages` set; if either side renames an attr without
    /// the other, the CLI starts asking for a target that doesn't
    /// exist. Lock the four spellings down.
    #[test]
    fn guest_image_attr_matches_flake_attribute_names() {
        assert_eq!(
            guest_image_attr(false, GuestSystem::Aarch64Linux),
            "agent-vm-guest-image-aarch64-linux",
        );
        assert_eq!(
            guest_image_attr(false, GuestSystem::X86_64Linux),
            "agent-vm-guest-image-x86_64-linux",
        );
        assert_eq!(
            guest_image_attr(true, GuestSystem::Aarch64Linux),
            "agent-vm-guest-proof-image-aarch64-linux",
        );
        assert_eq!(
            guest_image_attr(true, GuestSystem::X86_64Linux),
            "agent-vm-guest-proof-image-x86_64-linux",
        );
    }

    #[test]
    fn broker_image_attr_matches_flake_attribute_names() {
        assert_eq!(
            broker_image_attr(GuestSystem::Aarch64Linux),
            "broker-vm-image-aarch64-linux",
        );
        assert_eq!(
            broker_image_attr(GuestSystem::X86_64Linux),
            "broker-vm-image-x86_64-linux",
        );
    }
}
