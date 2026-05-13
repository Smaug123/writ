//! `writ-vm` — guest-side client for the host VM broker.
//!
//! This binary is intended to run inside daemon-managed Apple container VMs.
//! It consumes the injected `WRIT_BROKER_URL` and `WRIT_BROKER_TOKEN`
//! environment variables and exposes narrow VM-safe operations without ever
//! handling host-side GitHub credentials.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};

use writ::agent_run::{
    AgentProcessPlan, AgentPrompt, AgentRunId, AgentRunTerminalStatus, run_agent_process,
};
use writ::core::AgentKind;
use writ::vm_client::{
    VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV, VmClientConfig, VmClientConfigError, VmGitCloneCommand,
    VmGitPushCommand, VmWorkspaceInitCommand, clone_from_broker, fetch_agent_run_config,
    get_session_json, init_workspace_from_broker, push_to_broker, upload_agent_run_outcome,
};
use writ::vm_git::{GitBranchName, GitCloneRef, GitCloneRepo, GitObjectId, WorkspaceWarmMode};
use writ::vm_sandbox::{
    DEFAULT_PROBE_TIMEOUT, SandboxLeakProbe, default_leak_probes, run_sandbox_leak_probes,
};

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
    /// Agent runtime operations.
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// Sandbox self-tests run inside the VM before any broker traffic.
    Sandbox {
        #[command(subcommand)]
        action: SandboxCmd,
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
    /// Stage a Git push through the host broker for human review.
    ///
    /// All refs are explicit: `--branch`, `--new-head`, and either
    /// `--expected-remote-head <oid>` for a fast-forward update or
    /// `--create-branch` for a new branch with no upstream history.
    Push {
        /// Repository in owner/name form.
        repo: String,
        /// Branch name to push (without the `refs/heads/` prefix).
        #[arg(long)]
        branch: String,
        /// New commit object ID that the local branch must currently resolve to.
        #[arg(long = "new-head")]
        new_head: String,
        /// Object ID the upstream branch must currently point at, asserted by
        /// the human reviewer at promotion time. Mutually exclusive with
        /// `--create-branch`.
        #[arg(long = "expected-remote-head", conflicts_with = "create_branch")]
        expected_remote_head: Option<String>,
        /// Push creates the branch upstream — the bundle must contain its
        /// full history with no `--not` exclusion. Mutually exclusive with
        /// `--expected-remote-head`.
        #[arg(
            long = "create-branch",
            required_unless_present = "expected_remote_head"
        )]
        create_branch: bool,
        /// Local repository working directory containing the branch to push.
        #[arg(long)]
        workdir: PathBuf,
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

#[derive(Subcommand)]
enum SandboxCmd {
    /// Probe that the guest sandbox refuses external egress. Exits 0 on an
    /// intact sandbox; on a detected leak, prints the breach to stderr and
    /// exits non-zero. The guest bootstrap runs this before any broker
    /// traffic, so a sandbox break fails the session closed.
    Check,
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Fetch the brokered prompt and run the configured stage adapter.
    Run {
        /// Agent run UUID assigned by the host daemon.
        #[arg(long)]
        run_id: String,
        /// Session agent identity.
        #[arg(long, value_parser = parse_agent_kind)]
        agent: AgentKind,
        /// Test-only external fake adapter. The prompt is written to stdin.
        #[arg(long, hide = true)]
        fake_agent: Option<PathBuf>,
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
    // Exit unconditionally rather than falling off the end of main so the
    // tokio runtime does not block shutdown on detached `spawn_blocking`
    // work — notably the `getaddrinfo` thread that backs
    // `tokio::net::lookup_host`. If the sandbox DNS probe times out, that
    // thread keeps running until libc returns; `std::process::exit` lets
    // the process exit and the OS reaps it.
    let code = match run().await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let args = Args::parse();

    if let Cmd::Sandbox { action } = &args.cmd {
        return run_sandbox(action, &default_leak_probes(), DEFAULT_PROBE_TIMEOUT).await;
    }

    let config = config_from_args(&args)?;

    match args.cmd {
        Cmd::Sandbox { .. } => unreachable!("Sandbox dispatched above"),
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
            GitCmd::Push {
                repo,
                branch,
                new_head,
                expected_remote_head,
                create_branch,
                workdir,
                git,
            } => {
                let repo = parse_repo(&repo)?;
                let branch = parse_branch(&branch)?;
                let new_head = parse_object_id(&new_head)?;
                let expected_remote_head = match (expected_remote_head, create_branch) {
                    (Some(_), true) => unreachable!("clap conflicts_with rules out this case"),
                    (Some(oid), false) => Some(parse_object_id(&oid)?),
                    (None, true) => None,
                    (None, false) => unreachable!(
                        "clap required_unless_present rules out --expected-remote-head absent without --create-branch"
                    ),
                };
                let command = VmGitPushCommand::new(
                    repo,
                    branch,
                    new_head,
                    expected_remote_head,
                    workdir,
                    git,
                )?;
                let receipt = push_to_broker(&config, &command).await?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
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
        Cmd::Agent { action } => match action {
            AgentCmd::Run {
                run_id,
                agent,
                fake_agent,
            } => {
                let run_id = parse_agent_run_id(&run_id)?;
                let (prompt, model) = fetch_agent_run_config(&config, run_id).await?;
                run_stage_agent(
                    agent,
                    run_id,
                    &prompt,
                    &model,
                    &config,
                    fake_agent.as_deref(),
                )
                .await?;
            }
        },
    }
    Ok(())
}

async fn run_sandbox(
    action: &SandboxCmd,
    probes: &[SandboxLeakProbe],
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        SandboxCmd::Check => match run_sandbox_leak_probes(probes, timeout).await {
            Ok(()) => {
                println!("sandbox check ok");
                Ok(())
            }
            Err(leak) => Err(format!("sandbox leak: {leak}").into()),
        },
    }
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

fn parse_branch(raw: &str) -> Result<GitBranchName, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|error| format!("invalid Git branch name {raw:?}: {error}").into())
}

fn parse_object_id(raw: &str) -> Result<GitObjectId, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|error| format!("invalid Git object id {raw:?}: {error}").into())
}

fn parse_agent_kind(raw: &str) -> Result<AgentKind, String> {
    raw.parse::<AgentKind>().map_err(|error| error.to_string())
}

fn parse_agent_run_id(raw: &str) -> Result<AgentRunId, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|error| format!("invalid agent run ID {raw:?}: {error}").into())
}

async fn run_stage_agent(
    agent: AgentKind,
    run_id: AgentRunId,
    prompt: &AgentPrompt,
    model: &str,
    config: &VmClientConfig,
    fake_agent: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = match fake_agent {
        Some(program) => fake_agent_plan(agent, run_id, program)?,
        None => agent_process_plan(agent, run_id, model, config)?,
    };
    let log_root = std::env::temp_dir().join("writ-vm-agent-runs");
    let outcome = run_agent_process(&plan, prompt, &log_root)?;
    let agent_failed = outcome.status != AgentRunTerminalStatus::Succeeded;
    let exit_code = outcome.exit_code;
    upload_agent_run_outcome(config, &outcome).await?;
    if agent_failed {
        return Err(format!("agent exited with status code {exit_code}").into());
    }
    Ok(())
}

fn fake_agent_plan(
    agent: AgentKind,
    run_id: AgentRunId,
    program: &Path,
) -> Result<AgentProcessPlan, Box<dyn std::error::Error>> {
    Ok(AgentProcessPlan::new(run_id, program, [] as [OsString; 0])?
        .with_env_remove(VM_BROKER_URL_ENV)
        .with_env_remove(VM_BROKER_TOKEN_ENV)
        .with_env("WRIT_AGENT_KIND", agent.as_str()))
}

fn agent_process_plan(
    agent: AgentKind,
    run_id: AgentRunId,
    model: &str,
    config: &VmClientConfig,
) -> Result<AgentProcessPlan, Box<dyn std::error::Error>> {
    match agent {
        AgentKind::Claude => claude_process_plan(run_id, model, config),
        AgentKind::Codex => codex_process_plan(run_id, model, config),
    }
}

fn claude_process_plan(
    run_id: AgentRunId,
    model: &str,
    config: &VmClientConfig,
) -> Result<AgentProcessPlan, Box<dyn std::error::Error>> {
    let claude_config_dir = std::env::temp_dir().join("writ-vm-claude-code");
    std::fs::create_dir_all(&claude_config_dir)?;
    Ok(AgentProcessPlan::new(
        run_id,
        "claude",
        [
            OsString::from("--bare"),
            OsString::from("--print"),
            OsString::from("--model"),
            OsString::from(model),
            OsString::from("--effort"),
            OsString::from("low"),
            OsString::from("--output-format"),
            OsString::from("text"),
            OsString::from("--no-session-persistence"),
            OsString::from("--tools"),
            OsString::from(""),
        ],
    )?
    .with_env_remove(VM_BROKER_URL_ENV)
    .with_env_remove(VM_BROKER_TOKEN_ENV)
    .with_env_remove("ANTHROPIC_API_KEY")
    .with_env_remove("CLAUDE_CODE_OAUTH_TOKEN")
    .with_env("ANTHROPIC_BASE_URL", config.broker_url().as_str())
    .with_env("ANTHROPIC_AUTH_TOKEN", config.bearer_token().as_str())
    .with_env("CLAUDE_CONFIG_DIR", claude_config_dir.as_os_str())
    .with_env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    // The guest image installs the upstream claude binary directly, without
    // the nixpkgs wrapper that normally pins these. The VM has no outbound
    // network beyond the broker, so any auto-update or install check just
    // wastes time blocking on a connection it cannot make.
    .with_env("DISABLE_AUTOUPDATER", "1")
    .with_env("DISABLE_INSTALLATION_CHECKS", "1"))
}

fn codex_process_plan(
    run_id: AgentRunId,
    model: &str,
    config: &VmClientConfig,
) -> Result<AgentProcessPlan, Box<dyn std::error::Error>> {
    // Configure codex to treat the broker as an API-key-style provider:
    // `env_key="OPENAI_API_KEY"` makes codex read the broker bearer from
    // the env and send it as `Authorization: Bearer …`. The broker
    // performs the real ChatGPT-OAuth swap on the host side
    // (`Authorization`, `ChatGPT-Account-ID`, `X-OpenAI-Fedramp` are all
    // injected upstream by `VmHttpOpenAiProxyService`). Inside the VM
    // codex never goes down the ChatGPT-auth path and never tries to
    // refresh against `auth.openai.com` (which we couldn't reach
    // anyway).
    //
    // We set `supports_websockets=false` because the broker exposes
    // HTTP only; letting codex try wss:// first just wastes ~50s on
    // retries.
    let openai_base_url = format!("{}v1", config.broker_url().as_str());
    let provider_name_arg = "model_providers.writ-broker.name=\"writ broker\"";
    let provider_base_url_arg =
        format!("model_providers.writ-broker.base_url=\"{openai_base_url}\"");
    let provider_wire_api_arg = "model_providers.writ-broker.wire_api=\"responses\"";
    let provider_env_key_arg = "model_providers.writ-broker.env_key=\"OPENAI_API_KEY\"";
    let provider_supports_ws_arg = "model_providers.writ-broker.supports_websockets=false";
    let model_provider_arg = "model_provider=\"writ-broker\"";
    Ok(AgentProcessPlan::new(
        run_id,
        "codex",
        [
            OsString::from("exec"),
            OsString::from("--model"),
            OsString::from(model),
            OsString::from("--config"),
            OsString::from("model_reasoning_effort=low"),
            OsString::from("--config"),
            OsString::from("web_search=disabled"),
            OsString::from("--config"),
            OsString::from("tools.view_image=false"),
            OsString::from("--config"),
            OsString::from(provider_name_arg),
            OsString::from("--config"),
            OsString::from(provider_base_url_arg),
            OsString::from("--config"),
            OsString::from(provider_wire_api_arg),
            OsString::from("--config"),
            OsString::from(provider_env_key_arg),
            OsString::from("--config"),
            OsString::from(provider_supports_ws_arg),
            OsString::from("--config"),
            OsString::from(model_provider_arg),
            OsString::from("--json"),
            OsString::from("-"),
        ],
    )?
    .with_env_remove(VM_BROKER_URL_ENV)
    .with_env_remove(VM_BROKER_TOKEN_ENV)
    .with_env("OPENAI_API_KEY", config.bearer_token().as_str()))
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
    fn git_push_requires_either_create_branch_or_expected_remote_head() {
        let oid = "a".repeat(40);
        let result = Args::try_parse_from([
            "writ-vm",
            "git",
            "push",
            "owner/repo",
            "--branch",
            "feature/x",
            "--new-head",
            oid.as_str(),
            "--workdir",
            "/tmp/repo",
        ]);
        let err = match result {
            Ok(_) => panic!(
                "clap should reject the command without --create-branch or --expected-remote-head"
            ),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("--create-branch")
                || message.contains("create-branch")
                || message.contains("expected-remote-head"),
            "{message}"
        );
    }

    #[test]
    fn git_push_rejects_create_branch_combined_with_expected_remote_head() {
        let oid = "a".repeat(40);
        let other = "b".repeat(40);
        let result = Args::try_parse_from([
            "writ-vm",
            "git",
            "push",
            "owner/repo",
            "--branch",
            "feature/x",
            "--new-head",
            oid.as_str(),
            "--expected-remote-head",
            other.as_str(),
            "--create-branch",
            "--workdir",
            "/tmp/repo",
        ]);
        let err = match result {
            Ok(_) => {
                panic!("clap should reject --create-branch combined with --expected-remote-head")
            }
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("cannot be used") || message.contains("conflicts"),
            "{message}"
        );
    }

    #[test]
    fn git_push_accepts_explicit_expected_remote_head_form() {
        let new_head = "a".repeat(40);
        let expected = "b".repeat(40);
        let args = Args::try_parse_from([
            "writ-vm",
            "git",
            "push",
            "owner/repo",
            "--branch",
            "feature/x",
            "--new-head",
            new_head.as_str(),
            "--expected-remote-head",
            expected.as_str(),
            "--workdir",
            "/tmp/repo",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Git {
                action:
                    GitCmd::Push {
                        repo,
                        branch,
                        new_head: nh,
                        expected_remote_head,
                        create_branch,
                        workdir,
                        ..
                    },
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(branch, "feature/x");
                assert_eq!(nh, new_head);
                assert_eq!(expected_remote_head.as_deref(), Some(expected.as_str()));
                assert!(!create_branch);
                assert_eq!(workdir, PathBuf::from("/tmp/repo"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn git_push_accepts_create_branch_form() {
        let new_head = "a".repeat(40);
        let args = Args::try_parse_from([
            "writ-vm",
            "git",
            "push",
            "owner/repo",
            "--branch",
            "feature/new",
            "--new-head",
            new_head.as_str(),
            "--create-branch",
            "--workdir",
            "/tmp/repo",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Git {
                action:
                    GitCmd::Push {
                        expected_remote_head,
                        create_branch,
                        ..
                    },
            } => {
                assert!(expected_remote_head.is_none());
                assert!(create_branch);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn sandbox_check_parses_to_check_action() {
        let args = Args::try_parse_from(["writ-vm", "sandbox", "check"]).unwrap();
        assert!(matches!(
            args.cmd,
            Cmd::Sandbox {
                action: SandboxCmd::Check,
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sandbox_run_with_empty_probe_set_returns_ok() {
        // Run the sandbox dispatch with an injected empty probe set so the
        // test does not depend on host DNS, network egress, or
        // `lookup_host`'s blocking `getaddrinfo` task surviving timeout.
        // Empty probes mean `run_sandbox_leak_probes` finds no breach and
        // returns Ok, which lets us pin the dispatch signature without
        // taking a config or talking to the network.
        let result =
            run_sandbox(&SandboxCmd::Check, &[], Duration::from_millis(10)).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
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

    #[test]
    fn agent_run_accepts_run_id_and_agent_without_prompt_arg() {
        let args = Args::try_parse_from([
            "writ-vm",
            "agent",
            "run",
            "--run-id",
            "00000000-0000-0000-0000-000000000301",
            "--agent",
            "claude",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Agent {
                action:
                    AgentCmd::Run {
                        run_id,
                        agent,
                        fake_agent,
                    },
            } => {
                assert_eq!(run_id, "00000000-0000-0000-0000-000000000301");
                assert_eq!(agent, AgentKind::Claude);
                assert_eq!(fake_agent, None);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn claude_agent_plan_uses_low_cost_health_check_settings() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000302".parse().unwrap();
        let config = VmClientConfig::new("http://192.168.252.1:49152/", "writ-vm-secret").unwrap();

        let plan = claude_process_plan(run_id, "haiku", &config).unwrap();

        assert_eq!(plan.program(), std::path::Path::new("claude"));
        assert_eq!(
            plan.args(),
            &[
                OsString::from("--bare"),
                OsString::from("--print"),
                OsString::from("--model"),
                OsString::from("haiku"),
                OsString::from("--effort"),
                OsString::from("low"),
                OsString::from("--output-format"),
                OsString::from("text"),
                OsString::from("--no-session-persistence"),
                OsString::from("--tools"),
                OsString::from(""),
            ]
        );

        let env: std::collections::HashMap<&OsString, &OsString> =
            plan.env().iter().map(|(key, value)| (key, value)).collect();
        assert_eq!(
            env.get(&OsString::from("ANTHROPIC_BASE_URL"))
                .map(|v| v.to_str().unwrap()),
            Some("http://192.168.252.1:49152/"),
        );
        assert_eq!(
            env.get(&OsString::from("ANTHROPIC_AUTH_TOKEN"))
                .map(|v| v.to_str().unwrap()),
            Some("writ-vm-secret"),
        );
        assert_eq!(
            env.get(&OsString::from("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"))
                .map(|v| v.to_str().unwrap()),
            Some("1"),
        );
        assert_eq!(
            env.get(&OsString::from("DISABLE_AUTOUPDATER"))
                .map(|v| v.to_str().unwrap()),
            Some("1"),
        );
        assert_eq!(
            env.get(&OsString::from("DISABLE_INSTALLATION_CHECKS"))
                .map(|v| v.to_str().unwrap()),
            Some("1"),
        );
        assert!(env.contains_key(&OsString::from("CLAUDE_CONFIG_DIR")));

        let removed: std::collections::HashSet<&OsString> = plan.env_remove().iter().collect();
        for key in [
            VM_BROKER_URL_ENV,
            VM_BROKER_TOKEN_ENV,
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ] {
            assert!(
                removed.contains(&OsString::from(key)),
                "expected {key} to be removed from the Claude child env",
            );
        }
    }

    #[test]
    fn codex_agent_plan_uses_low_cost_health_check_settings() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000303".parse().unwrap();
        let config = VmClientConfig::new("http://192.168.252.1:49152/", "writ-vm-secret").unwrap();

        let plan = codex_process_plan(run_id, "gpt-5.4-mini", &config).unwrap();

        assert_eq!(plan.program(), std::path::Path::new("codex"));
        assert_eq!(
            plan.args(),
            &[
                OsString::from("exec"),
                OsString::from("--model"),
                OsString::from("gpt-5.4-mini"),
                OsString::from("--config"),
                OsString::from("model_reasoning_effort=low"),
                OsString::from("--config"),
                OsString::from("web_search=disabled"),
                OsString::from("--config"),
                OsString::from("tools.view_image=false"),
                OsString::from("--config"),
                OsString::from("model_providers.writ-broker.name=\"writ broker\""),
                OsString::from("--config"),
                OsString::from(
                    "model_providers.writ-broker.base_url=\"http://192.168.252.1:49152/v1\""
                ),
                OsString::from("--config"),
                OsString::from("model_providers.writ-broker.wire_api=\"responses\""),
                OsString::from("--config"),
                OsString::from("model_providers.writ-broker.env_key=\"OPENAI_API_KEY\""),
                OsString::from("--config"),
                OsString::from("model_providers.writ-broker.supports_websockets=false"),
                OsString::from("--config"),
                OsString::from("model_provider=\"writ-broker\""),
                OsString::from("--json"),
                OsString::from("-"),
            ]
        );

        let env: std::collections::HashMap<&OsString, &OsString> =
            plan.env().iter().map(|(key, value)| (key, value)).collect();
        assert!(
            !env.contains_key(&OsString::from("OPENAI_BASE_URL")),
            "OPENAI_BASE_URL is ignored by codex; the broker URL is passed via --config openai_base_url",
        );
        assert_eq!(
            env.get(&OsString::from("OPENAI_API_KEY"))
                .map(|v| v.to_str().unwrap()),
            Some("writ-vm-secret"),
            "OPENAI_API_KEY carries the broker bearer; the broker swaps it for the real ChatGPT credentials upstream",
        );

        let removed: std::collections::HashSet<&OsString> = plan.env_remove().iter().collect();
        for key in [VM_BROKER_URL_ENV, VM_BROKER_TOKEN_ENV] {
            assert!(
                removed.contains(&OsString::from(key)),
                "expected {key} to be removed from the Codex child env",
            );
        }
    }
}
