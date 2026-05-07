//! `writ` — the writ broker CLI client.
//!
//! Connects to the running daemon over a Unix socket and issues one
//! request per invocation. Designed to be called from agent bash blocks:
//!
//! ```bash
//! SESSION=$(writ open-session --label "fixing bug 42")
//! TOKEN=$(writ request "$SESSION" github contents read smaug123/writ)
//! git -c "http.extraheader=Authorization: Bearer $TOKEN" \
//!     clone https://github.com/smaug123/writ
//! writ close-session "$SESSION"
//! ```
//!
//! Successful output goes to stdout (session IDs, tokens). Errors go to
//! stderr and exit with code 1.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use writ::agent_run::AgentPrompt;
use writ::core::{AgentKind, CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, SessionId};
use writ::protocol::{AgentVmSessionInfo, ClientMessage, ServerMessage};
use writ::server::default_socket_path;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, WorkspaceWarmMode};

#[derive(Parser)]
#[command(name = "writ", about = "writ broker client")]
struct Args {
    /// Path to the broker Unix socket.
    #[arg(long, env = "WRIT_SOCKET")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open a new session and print its ID.
    OpenSession {
        /// Human-readable description stored in the audit log.
        #[arg(long)]
        label: Option<String>,
        /// Session agent identity used for GitHub App selection.
        #[arg(long, value_parser = parse_agent_kind)]
        agent: Option<AgentKind>,
        /// Agent model identifier stored in the audit log.
        #[arg(long)]
        model: Option<String>,
    },
    /// Close an open session.
    CloseSession { session_id: String },
    /// Request a credential for one capability.
    Request {
        session_id: String,
        #[command(subcommand)]
        backend: BackendCmd,
    },
    /// Start or stop daemon-managed agent VMs.
    AgentVm {
        #[command(subcommand)]
        action: AgentVmCmd,
    },
    /// Run an agent in a daemon-managed VM workspace.
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Bootstrap a repository workspace and run the selected agent there.
    Run {
        /// GitHub repository to clone into the VM before starting the agent.
        #[arg(long)]
        repo: String,
        /// Session agent identity used for GitHub App selection.
        #[arg(long, value_parser = parse_agent_kind)]
        agent: AgentKind,
        /// Prompt to pass to the selected agent.
        #[arg(long)]
        prompt: String,
        /// Human-readable description stored in the audit log.
        #[arg(long)]
        label: Option<String>,
        /// Agent model identifier stored in the audit log.
        #[arg(long)]
        model: Option<String>,
        /// Destination path for the clean checkout. Defaults to /workspace/<repo-name>.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Workspace warmup level to complete before starting the agent.
        #[arg(long, value_enum, default_value = "devshell")]
        warm: WorkspaceWarmArg,
    },
}

#[derive(Subcommand)]
enum AgentVmCmd {
    /// Start an isolated agent VM and print its session details.
    Start {
        /// Human-readable description stored in the audit log.
        #[arg(long)]
        label: Option<String>,
        /// Session agent identity used for GitHub App selection.
        #[arg(long, value_parser = parse_agent_kind)]
        agent: Option<AgentKind>,
        /// Agent model identifier stored in the audit log.
        #[arg(long)]
        model: Option<String>,
        /// GitHub repository to clone into the VM before starting the agent.
        #[arg(long)]
        repo: Option<String>,
        /// Destination path for the clean checkout. Defaults to /workspace/<repo-name>.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Workspace warmup level to complete before starting the agent.
        #[arg(long, value_enum)]
        warm: Option<WorkspaceWarmArg>,
        /// Command to run inside the VM after lifecycle preflight succeeds.
        #[arg(last = true, required = true)]
        guest_command: Vec<String>,
    },
    /// Stop a daemon-managed agent VM.
    Stop { session_id: String },
    /// List daemon-managed agent VM state records.
    List,
}

#[derive(Subcommand)]
enum BackendCmd {
    /// GitHub App installation-token backends.
    Github {
        #[command(subcommand)]
        action: GithubCmd,
    },
}

#[derive(Subcommand)]
enum GithubCmd {
    /// File contents (read or write).
    Contents { access: Access, repo: String },
    /// Issues (read or write).
    Issues { access: Access, repo: String },
    /// Pull requests (read or write).
    PullRequests { access: Access, repo: String },
    /// Repository metadata (always read-only).
    Metadata { repo: String },
}

#[derive(Clone, ValueEnum)]
enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq, ValueEnum)]
enum WorkspaceWarmArg {
    None,
    Sources,
    #[value(name = "devshell", alias = "dev-shell")]
    DevShell,
}

impl From<Access> for GitHubAccess {
    fn from(a: Access) -> Self {
        match a {
            Access::Read => GitHubAccess::Read,
            Access::Write => GitHubAccess::Write,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let socket_path = args.socket.unwrap_or_else(default_socket_path);

    match args.cmd {
        Cmd::OpenSession {
            label,
            agent,
            model,
        } => {
            let msg = ClientMessage::OpenSession {
                label,
                agent_kind: agent,
                agent_model: model,
            };
            match call(&socket_path, &msg)? {
                ServerMessage::SessionOpened { session_id } => println!("{session_id}"),
                ServerMessage::Error { message } => return Err(message.into()),
                other => return Err(format!("unexpected response: {other:?}").into()),
            }
        }

        Cmd::CloseSession { session_id } => {
            let id: SessionId = session_id
                .parse()
                .map_err(|e| format!("invalid session ID: {e}"))?;
            let msg = ClientMessage::CloseSession { session_id: id };
            match call(&socket_path, &msg)? {
                ServerMessage::SessionClosed => {}
                ServerMessage::Error { message } => return Err(message.into()),
                other => return Err(format!("unexpected response: {other:?}").into()),
            }
        }

        Cmd::Request {
            session_id,
            backend,
        } => {
            let id: SessionId = session_id
                .parse()
                .map_err(|e| format!("invalid session ID: {e}"))?;

            let capability = build_capability(backend)?;
            let msg = ClientMessage::Request {
                session_id: id,
                capability,
            };

            match call(&socket_path, &msg)? {
                ServerMessage::TokenGranted { token, .. } => println!("{token}"),
                ServerMessage::Denied { reason } => return Err(format!("denied: {reason}").into()),
                ServerMessage::Error { message } => return Err(message.into()),
                other => return Err(format!("unexpected response: {other:?}").into()),
            }
        }

        Cmd::AgentVm { action } => match action {
            AgentVmCmd::Start {
                label,
                agent,
                model,
                repo,
                workspace,
                warm,
                guest_command,
            } => {
                let workspace = build_workspace_bootstrap(repo, workspace, warm)?;
                start_agent_vm(&socket_path, label, agent, model, workspace, guest_command)?;
            }
            AgentVmCmd::Stop { session_id } => {
                let id: SessionId = session_id
                    .parse()
                    .map_err(|e| format!("invalid session ID: {e}"))?;
                let msg = ClientMessage::StopAgentVm { session_id: id };
                match call_with_timeout(&socket_path, &msg, AGENT_VM_CALL_TIMEOUT)? {
                    ServerMessage::AgentVmStopped => {}
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            AgentVmCmd::List => {
                let msg = ClientMessage::ListAgentVms;
                match call_with_timeout(&socket_path, &msg, AGENT_VM_CALL_TIMEOUT)? {
                    ServerMessage::AgentVmSessions { sessions } => {
                        let mut out = std::io::stdout().lock();
                        write_agent_vm_sessions(&mut out, &sessions)?;
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
        },
        Cmd::Agent { action } => match action {
            AgentCmd::Run {
                repo,
                agent,
                prompt,
                label,
                model,
                workspace,
                warm,
            } => {
                let warm_mode = warm.into();
                let workspace = build_workspace_bootstrap_from_repo(repo, workspace, warm_mode)?;
                start_agent_run(
                    &socket_path,
                    label,
                    agent,
                    model,
                    workspace,
                    AgentPrompt::try_new(prompt)?,
                )?;
            }
        },
    }
    Ok(())
}

fn parse_agent_kind(raw: &str) -> Result<AgentKind, String> {
    raw.parse::<AgentKind>().map_err(|err| err.to_string())
}

fn start_agent_vm(
    socket_path: &Path,
    label: Option<String>,
    agent_kind: Option<AgentKind>,
    agent_model: Option<String>,
    workspace: Option<AgentVmWorkspaceBootstrap>,
    guest_command: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = if workspace.is_some() {
        AGENT_VM_WORKSPACE_CALL_TIMEOUT
    } else {
        AGENT_VM_CALL_TIMEOUT
    };
    let msg = ClientMessage::StartAgentVm {
        label,
        agent_kind,
        agent_model,
        workspace,
        guest_command,
    };
    match call_with_timeout(socket_path, &msg, timeout)? {
        ServerMessage::AgentVmStarted {
            session_id,
            broker_url,
        } => {
            println!("session_id={session_id}");
            println!("broker_url={broker_url}");
            Ok(())
        }
        ServerMessage::Error { message } => Err(message.into()),
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

fn start_agent_run(
    socket_path: &Path,
    label: Option<String>,
    agent_kind: AgentKind,
    agent_model: Option<String>,
    workspace: AgentVmWorkspaceBootstrap,
    prompt: AgentPrompt,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = ClientMessage::StartAgentRun {
        label,
        agent_kind,
        agent_model,
        workspace,
        prompt,
    };
    match call_with_timeout(socket_path, &msg, AGENT_VM_WORKSPACE_CALL_TIMEOUT)? {
        ServerMessage::AgentRunStarted {
            session_id,
            run_id,
            broker_url,
        } => {
            println!("session_id={session_id}");
            println!("run_id={run_id}");
            println!("broker_url={broker_url}");
            Ok(())
        }
        ServerMessage::Error { message } => Err(message.into()),
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

fn build_workspace_bootstrap(
    repo: Option<String>,
    destination: Option<PathBuf>,
    warm: Option<WorkspaceWarmArg>,
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
        warm.unwrap_or(WorkspaceWarmArg::DevShell).into(),
    )
    .map(Some)
}

fn build_workspace_bootstrap_from_repo(
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

impl From<WorkspaceWarmArg> for WorkspaceWarmMode {
    fn from(value: WorkspaceWarmArg) -> Self {
        match value {
            WorkspaceWarmArg::None => Self::None,
            WorkspaceWarmArg::Sources => Self::Sources,
            WorkspaceWarmArg::DevShell => Self::DevShell,
        }
    }
}

fn build_capability(backend: BackendCmd) -> Result<CapabilityRequest, Box<dyn std::error::Error>> {
    let BackendCmd::Github { action } = backend;
    let repo_str = match &action {
        GithubCmd::Contents { repo, .. }
        | GithubCmd::Issues { repo, .. }
        | GithubCmd::PullRequests { repo, .. }
        | GithubCmd::Metadata { repo } => repo.clone(),
    };
    let repo: RepoRef = repo_str
        .parse()
        .map_err(|e| format!("invalid repo '{repo_str}': {e}"))?;

    let github_req = match action {
        GithubCmd::Contents { access, .. } => GitHubRequest::Contents {
            access: access.into(),
            repo,
        },
        GithubCmd::Issues { access, .. } => GitHubRequest::Issues {
            access: access.into(),
            repo,
        },
        GithubCmd::PullRequests { access, .. } => GitHubRequest::PullRequests {
            access: access.into(),
            repo,
        },
        GithubCmd::Metadata { .. } => GitHubRequest::Metadata { repo },
    };
    Ok(CapabilityRequest::GitHub(github_req))
}

fn write_agent_vm_sessions(
    out: &mut dyn Write,
    sessions: &[AgentVmSessionInfo],
) -> std::io::Result<()> {
    for (index, session) in sessions.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "session_id={}", session.session_id)?;
        writeln!(out, "status={}", session.status.as_str())?;
        writeln!(out, "subnet_index={}", session.subnet_index)?;
        writeln!(
            out,
            "runtime={}",
            if session.runtime_attached {
                "attached"
            } else {
                "detached"
            }
        )?;
        writeln!(out, "vm={}", session.vm_name)?;
        writeln!(out, "network={}", session.network_name)?;
        for broker_url in &session.broker_urls {
            writeln!(out, "broker_url={broker_url}")?;
        }
    }
    Ok(())
}

/// One request, one reply. If the broker takes longer than this to
/// respond, something is wrong and the CLI should bail rather than
/// hang a shell pipeline. 60s is already far above any healthy
/// round-trip (the broker's own IDLE_READ_TIMEOUT is 60s, and a
/// healthy request/reply is milliseconds).
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
// Apple Container startup/teardown can include image cold-start, PF work, guest
// preflight probes. Keep the CLI patient enough that the daemon can return a
// definitive started/rolled-back result; a wedged daemon can hold the CLI until
// this same bound expires. The broker's idle read timeout is between request
// reads, not a response wall-time cap.
const AGENT_VM_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
// Workspace starts may spend most of their time waiting for Nix substitute
// prefetching, and the daemon's workspace bootstrap timeout is 20 minutes.
const AGENT_VM_WORKSPACE_CALL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);

fn call(
    socket_path: &Path,
    msg: &ClientMessage,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    call_with_timeout(socket_path, msg, CALL_TIMEOUT)
}

fn call_with_timeout(
    socket_path: &Path,
    msg: &ClientMessage,
    timeout: std::time::Duration,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("cannot connect to {}: {e}", socket_path.display()))?;
    // Apply to both sides so a stuck broker can't wedge the CLI on
    // either write or read.
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut line = serde_json::to_string(msg)?;
    line.push('\n');

    let mut w = &stream;
    w.write_all(line.as_bytes())?;
    w.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut reply = String::new();
    reader.read_line(&mut reply)?;

    Ok(serde_json::from_str(reply.trim_end_matches('\n'))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_vm_list_output_is_key_value_and_marks_runtime_attachment() {
        let detached_id: SessionId = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let attached_id: SessionId = "b7960f37-3888-48a9-b0bb-a4edcaab2194".parse().unwrap();
        let sessions = vec![
            AgentVmSessionInfo {
                session_id: detached_id,
                status: writ::agent_vm_lifecycle::AgentVmSessionStateStatus::Running,
                subnet_index: 252,
                vm_name: format!("writ-agent-vm-{detached_id}"),
                network_name: format!("writ-agent-net-{detached_id}"),
                broker_urls: vec!["http://192.168.252.1:51375/".into()],
                runtime_attached: false,
            },
            AgentVmSessionInfo {
                session_id: attached_id,
                status: writ::agent_vm_lifecycle::AgentVmSessionStateStatus::Starting,
                subnet_index: 253,
                vm_name: format!("writ-agent-vm-{attached_id}"),
                network_name: format!("writ-agent-net-{attached_id}"),
                broker_urls: vec!["http://192.168.253.1:51376/".into()],
                runtime_attached: true,
            },
        ];
        let mut out = Vec::new();

        write_agent_vm_sessions(&mut out, &sessions).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "session_id=51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "status=running\n",
                "subnet_index=252\n",
                "runtime=detached\n",
                "vm=writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "network=writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "broker_url=http://192.168.252.1:51375/\n",
                "\n",
                "session_id=b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "status=starting\n",
                "subnet_index=253\n",
                "runtime=attached\n",
                "vm=writ-agent-vm-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "network=writ-agent-net-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "broker_url=http://192.168.253.1:51376/\n",
            )
        );
    }

    #[test]
    fn workspace_related_flags_require_repo() {
        assert!(
            build_workspace_bootstrap(None, Some(PathBuf::from("/workspace/repo")), None)
                .unwrap_err()
                .to_string()
                .contains("--workspace requires --repo")
        );
        assert!(
            build_workspace_bootstrap(None, None, Some(WorkspaceWarmArg::Sources))
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
            Some(WorkspaceWarmArg::None),
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
    fn agent_run_cli_accepts_agent_repo_prompt_and_warmup() {
        let args = Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "claude",
            "--prompt",
            "fix the failing test",
            "--warm",
            "sources",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Agent {
                action:
                    AgentCmd::Run {
                        repo,
                        agent,
                        prompt,
                        warm,
                        ..
                    },
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(agent, AgentKind::Claude);
                assert_eq!(prompt, "fix the failing test");
                assert_eq!(warm, WorkspaceWarmArg::Sources);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_run_cli_defaults_to_devshell_warmup() {
        let args = Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "codex",
            "--prompt",
            "fix it",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Agent {
                action: AgentCmd::Run { warm, .. },
            } => assert_eq!(warm, WorkspaceWarmArg::DevShell),
            _ => panic!("unexpected command"),
        }
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

    #[test]
    fn agent_run_protocol_message_redacts_prompt_in_debug() {
        let workspace = build_workspace_bootstrap_from_repo(
            "owner/repo".into(),
            None,
            WorkspaceWarmMode::DevShell,
        )
        .unwrap();
        let msg = ClientMessage::StartAgentRun {
            label: None,
            agent_kind: AgentKind::Claude,
            agent_model: None,
            workspace,
            prompt: AgentPrompt::try_new("SECRET prompt").unwrap(),
        };

        let debug = format!("{msg:?}");

        assert!(!debug.contains("SECRET prompt"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}
