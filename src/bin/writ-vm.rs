//! `writ-vm` — guest-side client for the host VM broker.
//!
//! This binary is intended to run inside daemon-managed Apple container VMs.
//! It consumes the injected `WRIT_BROKER_URL` and `WRIT_BROKER_TOKEN`
//! environment variables and exposes narrow VM-safe operations without ever
//! handling host-side GitHub credentials.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use writ::vm_client::{
    VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV, VmClientConfig, VmClientConfigError, VmGitCloneCommand,
    VmWorkspaceInitCommand, clone_from_broker, get_session_json, init_workspace_from_broker,
};
use writ::vm_git::{GitCloneRef, GitCloneRepo, WorkspaceWarmMode};

#[derive(Parser)]
#[command(name = "writ-vm", about = "guest-side writ VM broker client")]
struct Args {
    /// VM broker base URL injected by the daemon.
    #[arg(long, env = VM_BROKER_URL_ENV)]
    broker_url: Option<String>,
    /// VM bearer token injected by the daemon.
    #[arg(long, env = VM_BROKER_TOKEN_ENV, hide_env_values = true)]
    broker_token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the VM session descriptor as JSON.
    Session,
    /// Git operations mediated by the host broker.
    Git {
        #[command(subcommand)]
        action: GitCmd,
    },
    /// Workspace operations mediated by the host broker.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceCmd,
    },
}

#[derive(Subcommand)]
enum GitCmd {
    /// Clone a GitHub repository through the host broker.
    Clone {
        /// Repository in owner/name form.
        repo: String,
        /// Destination checkout path. Defaults to the repository name.
        destination: Option<PathBuf>,
        /// Optional branch, tag, or ref to clone.
        #[arg(long = "ref")]
        git_ref: Option<String>,
        /// Git executable inside the guest.
        #[arg(long, default_value = "git")]
        git: PathBuf,
    },
}

#[derive(Subcommand)]
enum WorkspaceCmd {
    /// Initialise a clean workspace checkout through the host broker.
    Init {
        /// Repository in owner/name form.
        repo: String,
        /// Destination checkout path. Defaults to /workspace/<repo-name>.
        destination: Option<PathBuf>,
        /// Warmup level to complete before returning.
        #[arg(long, default_value = "devshell")]
        warm: WorkspaceWarmArg,
        /// Git executable inside the guest.
        #[arg(long, default_value = "git")]
        git: PathBuf,
        /// Nix executable inside the guest.
        #[arg(long, default_value = "nix")]
        nix: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum WorkspaceWarmArg {
    None,
    Sources,
    #[value(name = "devshell", alias = "dev-shell")]
    DevShell,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = config_from_args(&args)?;

    match args.cmd {
        Cmd::Session => {
            let session = get_session_json(&config).await?;
            println!("{}", serde_json::to_string_pretty(&session)?);
        }
        Cmd::Git { action } => match action {
            GitCmd::Clone {
                repo,
                destination,
                git_ref,
                git,
            } => {
                let repo = parse_repo(&repo)?;
                let git_ref = git_ref.as_deref().map(parse_git_ref).transpose()?;
                let command = VmGitCloneCommand::new(repo, git_ref, destination, git)?;
                let destination = clone_from_broker(&config, &command).await?;
                println!("{}", destination.display());
            }
        },
        Cmd::Workspace { action } => match action {
            WorkspaceCmd::Init {
                repo,
                destination,
                warm,
                git,
                nix,
            } => {
                let repo = parse_repo(&repo)?;
                let command =
                    VmWorkspaceInitCommand::new(repo, destination, warm.into(), git, nix)?;
                let destination = init_workspace_from_broker(&config, &command).await?;
                println!("{}", destination.display());
            }
        },
    }
    Ok(())
}

fn config_from_args(args: &Args) -> Result<VmClientConfig, VmClientConfigError> {
    let broker_url = match &args.broker_url {
        Some(value) => value.clone(),
        None => return Err(VmClientConfigError::MissingEnv(VM_BROKER_URL_ENV)),
    };
    let broker_token = match &args.broker_token {
        Some(value) => value.clone(),
        None => return Err(VmClientConfigError::MissingEnv(VM_BROKER_TOKEN_ENV)),
    };
    VmClientConfig::new(broker_url, broker_token)
}

fn parse_repo(raw: &str) -> Result<GitCloneRepo, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|error| format!("invalid GitHub repository {raw:?}: {error}").into())
}

fn parse_git_ref(raw: &str) -> Result<GitCloneRef, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|error| format!("invalid Git ref {raw:?}: {error}").into())
}

impl From<WorkspaceWarmArg> for WorkspaceWarmMode {
    fn from(value: WorkspaceWarmArg) -> Self {
        match value {
            WorkspaceWarmArg::None => Self::None,
            WorkspaceWarmArg::Sources => Self::Sources,
            WorkspaceWarmArg::DevShell => Self::DevShell,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::CommandFactory;

    use super::*;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // Process environment mutation is isolated to this binary's unit
            // test process and guarded so the previous value is restored.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn help_does_not_print_broker_token_env_value() {
        let _guard = EnvGuard::set(VM_BROKER_TOKEN_ENV, "writ-vm-secret");
        let mut command = Args::command();
        let mut help = Vec::new();

        command.write_long_help(&mut help).unwrap();

        let help = String::from_utf8(help).unwrap();
        assert!(help.contains(VM_BROKER_TOKEN_ENV), "{help}");
        assert!(!help.contains("writ-vm-secret"), "{help}");
    }

    #[test]
    fn workspace_init_accepts_warm_none() {
        let args = Args::try_parse_from([
            "writ-vm",
            "workspace",
            "init",
            "owner/repo",
            "--warm",
            "none",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Workspace {
                action:
                    WorkspaceCmd::Init {
                        repo,
                        destination,
                        warm,
                        ..
                    },
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(destination, None);
                assert_eq!(warm, WorkspaceWarmArg::None);
            }
            _ => panic!("unexpected command"),
        }
    }
}
