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
    clone_from_broker, get_session_json,
};
use writ::vm_git::{GitCloneRef, GitCloneRepo};

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
}
