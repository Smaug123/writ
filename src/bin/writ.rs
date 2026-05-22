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

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

use writ::agent_run::{AgentPrompt, CorrelationId};
use writ::cli::identity::{capture_operator_identity, resolve_reconcile_outcome};
use writ::cli::output::{
    write_agent_vm_sessions, write_staged_push_detail, write_staged_push_summaries,
};
use writ::cli::parse::{parse_agent_kind, parse_correlation_id};
use writ::cli::workspace::{
    GuestSystem, build_workspace_bootstrap, build_workspace_bootstrap_from_repo,
    default_guest_system, guest_image_attr,
};
use writ::core::{
    AgentKind, CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, RequestId, SessionId,
};
use writ::protocol::{ClientMessage, RejectionReason, ServerMessage};
use writ::server::default_socket_path;
use writ::vm_git::{AgentVmWorkspaceBootstrap, WorkspaceWarmMode};

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
    /// Inspect VM-staged git pushes awaiting promotion review.
    Promote {
        #[command(subcommand)]
        action: PromoteCmd,
    },
}

#[derive(Subcommand)]
enum PromoteCmd {
    /// List every staged push the broker is holding for review, optionally
    /// filtered to one audit session. Filtering exists so an operator (or
    /// the bailiff promote workflow) can isolate the pushes a single run
    /// produced without scanning every pending staged entry on disk.
    List {
        /// Audit session id to restrict the listing to. When omitted, the
        /// broker returns every staged push it is holding.
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Show the full detail of one staged push, including its audit context.
    Show { request_id: String },
    /// Reject a staged push: records the operator decision in the audit
    /// log and removes the staging directory. The operator identity is
    /// taken from `$USER` (or `unknown` if unset); the host is trusted to
    /// assert its own identity over the local broker socket.
    Reject {
        request_id: String,
        /// Human-readable justification recorded verbatim in the audit row.
        #[arg(long)]
        reason: String,
    },
    /// Reconcile a quarantined staged push by recording an operator's
    /// out-of-band observation of GitHub. Used when a prior approve
    /// attempt left the push in a blocking state — `Resolved(PostPatchFailure)`
    /// or a boot-observed `Uncertain` — that the broker can't clear on
    /// its own. Exactly one of `--confirmed-applied` and
    /// `--confirmed-not-applied` must be passed.
    ///
    /// `--confirmed-applied` records that the operator confirmed the
    /// PATCH did land on GitHub; the broker writes a born-terminal
    /// reconciliation row that supersedes the predecessor and a
    /// `git_push_resolution(decision='approved')` row. `--new-app-tip`
    /// is the App-side commit SHA the operator observed on the branch
    /// and `--reason` carries the human-readable justification stored
    /// verbatim on the audit row.
    ///
    /// `--confirmed-not-applied` records that the operator confirmed
    /// the PATCH did NOT land; the broker writes only the
    /// reconciliation row (no resolution), so the push becomes
    /// rejectable/retryable. `--detail` carries the audit-row
    /// justification.
    ///
    /// As with reject/approve, the operator identity is taken from
    /// `$USER` (or `unknown` if unset).
    #[command(group(
        ArgGroup::new("reconcile_verdict")
            .required(true)
            .args(["confirmed_applied", "confirmed_not_applied"])
    ))]
    Reconcile {
        request_id: String,
        /// Record that the operator confirmed the PATCH landed on
        /// GitHub. Requires `--new-app-tip` and `--reason`.
        #[arg(long)]
        confirmed_applied: bool,
        /// Record that the operator confirmed the PATCH did NOT land
        /// on GitHub. Requires `--detail`.
        #[arg(long)]
        confirmed_not_applied: bool,
        /// App-side commit SHA the operator observed at the branch tip
        /// on GitHub. Required with `--confirmed-applied`; forbidden
        /// with `--confirmed-not-applied` so a mistyped verdict can't
        /// silently discard a SHA the operator meant to record.
        #[arg(
            long,
            required_if_eq("confirmed_applied", "true"),
            conflicts_with = "confirmed_not_applied"
        )]
        new_app_tip: Option<String>,
        /// Human-readable justification recorded verbatim on the
        /// reconciliation audit row. Required with `--confirmed-applied`;
        /// forbidden with `--confirmed-not-applied` (use `--detail`).
        #[arg(
            long,
            required_if_eq("confirmed_applied", "true"),
            conflicts_with = "confirmed_not_applied"
        )]
        reason: Option<String>,
        /// Human-readable detail recorded verbatim on the
        /// reconciliation audit row. Required with
        /// `--confirmed-not-applied`; forbidden with `--confirmed-applied`
        /// (use `--reason`).
        #[arg(
            long,
            required_if_eq("confirmed_not_applied", "true"),
            conflicts_with = "confirmed_applied"
        )]
        detail: Option<String>,
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
        /// Agent model identifier passed through to the guest agent CLI
        /// (e.g. codex's `--model`) and stored in the audit log.
        #[arg(long)]
        model: String,
        /// Destination path for the clean checkout. Defaults to /workspace/<repo-name>.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Workspace warmup level to complete before starting the agent.
        #[arg(long, value_enum, default_value = "devshell")]
        warm: WorkspaceWarmArg,
        /// Opaque caller-supplied id that ties this run to a wider
        /// task. Validated only as a safe id (`[A-Za-z0-9_-]`, 1..=64
        /// bytes); the broker never interprets the contents.
        #[arg(long, value_parser = parse_correlation_id)]
        correlation_id: Option<CorrelationId>,
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
    /// Build the agent VM guest OCI image from the repo's Nix flake and
    /// load it into the local Apple container image store. Mirrors what
    /// the `scripts/prove-agent-vm-*.sh` proof harnesses do before they
    /// boot a guest. macOS-only — the `container` CLI is Apple's.
    BuildImage {
        /// Build the proof variant (`agent-vm-guest-proof-image-*`,
        /// which bundles `ip`, `wget`, and `nslookup`) instead of the
        /// default production guest image.
        #[arg(long)]
        proof: bool,
        /// Guest system to target. Defaults to mapping the host CPU
        /// architecture to `aarch64-linux` or `x86_64-linux`, matching
        /// the proof harness's `default_guest_system` helper.
        #[arg(long, value_enum)]
        guest_system: Option<GuestSystemArg>,
        /// Flake reference passed to `nix build`. Defaults to `.` so
        /// the command works when invoked from the repo root.
        #[arg(long, default_value = ".")]
        flake: String,
    },
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

/// Guest OCI image target system, mirroring the flake's
/// `agent-vm-guest-image-<system>` attribute suffixes. The proof
/// harnesses derive this from `uname -m`; we mirror the same mapping
/// against `std::env::consts::ARCH` so the CLI default lines up with
/// the script behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum GuestSystemArg {
    #[value(name = "aarch64-linux")]
    Aarch64Linux,
    #[value(name = "x86_64-linux")]
    X86_64Linux,
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
    writ::telemetry::init("warn")?;
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
                ServerMessage::UnknownSession { session_id } => {
                    return Err(format!("unknown session {session_id}").into());
                }
                ServerMessage::ClosedSession { session_id } => {
                    return Err(format!("session {session_id} is closed").into());
                }
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
                let workspace =
                    build_workspace_bootstrap(repo, workspace, warm.map(WorkspaceWarmMode::from))?;
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
                let msg = ClientMessage::ListAgentVms {};
                match call_with_timeout(&socket_path, &msg, AGENT_VM_CALL_TIMEOUT)? {
                    ServerMessage::AgentVmSessions { sessions } => {
                        let mut out = std::io::stdout().lock();
                        write_agent_vm_sessions(&mut out, &sessions)?;
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            AgentVmCmd::BuildImage {
                proof,
                guest_system,
                flake,
            } => {
                build_agent_vm_guest_image(proof, guest_system, &flake)?;
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
                correlation_id,
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
                    correlation_id,
                )?;
            }
        },
        Cmd::Promote { action } => match action {
            PromoteCmd::List { session_id } => {
                let session_id = session_id
                    .map(|raw| {
                        raw.parse::<SessionId>()
                            .map_err(|e| format!("invalid session id: {e}"))
                    })
                    .transpose()?;
                let msg = ClientMessage::ListStagedPushes { session_id };
                match call(&socket_path, &msg)? {
                    ServerMessage::StagedPushes { mut pushes } => {
                        // Disk iteration order is unspecified; sort here so the
                        // CLI output is deterministic and oldest-first.
                        pushes.sort_by_key(|p| p.staged_at);
                        let mut out = std::io::stdout().lock();
                        write_staged_push_summaries(&mut out, &pushes)?;
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            PromoteCmd::Show { request_id } => {
                let id: RequestId = request_id
                    .parse()
                    .map_err(|e| format!("invalid request ID: {e}"))?;
                let msg = ClientMessage::ShowStagedPush { request_id: id };
                match call(&socket_path, &msg)? {
                    ServerMessage::StagedPush { push } => {
                        let mut out = std::io::stdout().lock();
                        write_staged_push_detail(&mut out, &push)?;
                    }
                    ServerMessage::UnknownStagedPush { request_id } => {
                        return Err(format!("no staged push with id {request_id}").into());
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            PromoteCmd::Reject { request_id, reason } => {
                let id: RequestId = request_id
                    .parse()
                    .map_err(|e| format!("invalid request ID: {e}"))?;
                let reason = RejectionReason::try_new(reason).map_err(|e| e.to_string())?;
                let operator = capture_operator_identity();
                let msg = ClientMessage::RejectStagedPush {
                    request_id: id,
                    operator,
                    reason,
                };
                match call(&socket_path, &msg)? {
                    ServerMessage::StagedPushRejected { request_id } => {
                        println!("rejected push_request_id={request_id}");
                    }
                    ServerMessage::UnknownStagedPush { request_id } => {
                        return Err(format!("no staged push with id {request_id}").into());
                    }
                    ServerMessage::StagedPushAlreadyResolved { request_id } => {
                        return Err(format!(
                            "staged push {request_id} already has an operator decision recorded",
                        )
                        .into());
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            PromoteCmd::Reconcile {
                request_id,
                confirmed_applied,
                confirmed_not_applied,
                new_app_tip,
                reason,
                detail,
            } => {
                let id: RequestId = request_id
                    .parse()
                    .map_err(|e| format!("invalid request ID: {e}"))?;
                let outcome = resolve_reconcile_outcome(
                    confirmed_applied,
                    confirmed_not_applied,
                    new_app_tip,
                    reason,
                    detail,
                )?;
                let operator = capture_operator_identity();
                let msg = ClientMessage::ReconcileStagedPush {
                    request_id: id,
                    operator,
                    outcome,
                };
                match call(&socket_path, &msg)? {
                    ServerMessage::StagedPushReconciled { request_id } => {
                        println!("reconciled push_request_id={request_id}");
                    }
                    ServerMessage::UnknownStagedPush { request_id } => {
                        return Err(format!("no staged push with id {request_id}").into());
                    }
                    ServerMessage::StagedPushAlreadyResolved { request_id } => {
                        return Err(format!(
                            "staged push {request_id} already has an operator decision recorded",
                        )
                        .into());
                    }
                    ServerMessage::StagedPushNotReconcilable { request_id, reason } => {
                        return Err(format!(
                            "staged push {request_id} is not reconcilable: {reason}",
                        )
                        .into());
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
        },
    }
    Ok(())
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
    agent_model: String,
    workspace: AgentVmWorkspaceBootstrap,
    prompt: AgentPrompt,
    correlation_id: Option<CorrelationId>,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = ClientMessage::StartAgentRun {
        label,
        agent_kind,
        agent_model,
        workspace,
        prompt,
        correlation_id,
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

/// Build the agent VM guest OCI image with Nix and load it into the
/// local Apple container store. Mirrors the `load_guest_image` shell
/// helper used by the proof harnesses in `scripts/`.
///
/// The `nix build` step is run with stderr inherited so the user sees
/// substituter progress; stdout is captured because that's where
/// `--print-out-paths` writes the store path. The `container image
/// load` step inherits both so any tag/manifest output reaches the
/// terminal.
fn build_agent_vm_guest_image(
    proof: bool,
    guest_system: Option<GuestSystemArg>,
    flake: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::consts::OS != "macos" {
        return Err(format!(
            "writ agent-vm build-image is macOS-only (Apple container CLI required); host OS is {}",
            std::env::consts::OS,
        )
        .into());
    }
    let guest_system = match guest_system {
        Some(g) => GuestSystem::from(g),
        None => default_guest_system(std::env::consts::ARCH)?,
    };
    let attr = guest_image_attr(proof, guest_system);
    let flake_ref = format!("{flake}#{attr}");

    eprintln!("building {flake_ref}");
    let nix_output = std::process::Command::new("nix")
        .args([
            "build",
            "--no-link",
            "--print-out-paths",
            flake_ref.as_str(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("failed to spawn nix: {e}"))?;
    if !nix_output.status.success() {
        return Err(format!(
            "nix build {flake_ref} failed with status {}",
            nix_output.status
        )
        .into());
    }
    let archive = String::from_utf8(nix_output.stdout)
        .map_err(|e| format!("nix build stdout was not valid UTF-8: {e}"))?
        .trim()
        .to_string();
    if archive.is_empty() {
        return Err("nix build printed no store path".into());
    }
    eprintln!("loading {archive} into Apple container store");
    let load_status = std::process::Command::new("container")
        .args(["image", "load", "--input", archive.as_str()])
        .status()
        .map_err(|e| format!("failed to spawn `container`: {e}"))?;
    if !load_status.success() {
        return Err(format!("container image load failed with status {load_status}").into());
    }
    println!("{archive}");
    Ok(())
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

impl From<GuestSystemArg> for GuestSystem {
    fn from(value: GuestSystemArg) -> Self {
        match value {
            GuestSystemArg::Aarch64Linux => Self::Aarch64Linux,
            GuestSystemArg::X86_64Linux => Self::X86_64Linux,
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
    fn agent_run_cli_accepts_agent_repo_prompt_and_warmup() {
        let args = Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "claude",
            "--model",
            "claude-test",
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
                        model,
                        warm,
                        correlation_id,
                        ..
                    },
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(agent, AgentKind::Claude);
                assert_eq!(prompt, "fix the failing test");
                assert_eq!(model, "claude-test");
                assert_eq!(warm, WorkspaceWarmArg::Sources);
                assert!(correlation_id.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_run_cli_accepts_correlation_id_flag() {
        let args = Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "codex",
            "--model",
            "gpt-5.4-mini",
            "--prompt",
            "fix it",
            "--correlation-id",
            "feat-42_xyz",
        ])
        .unwrap();

        match args.cmd {
            Cmd::Agent {
                action: AgentCmd::Run { correlation_id, .. },
            } => {
                let id = correlation_id.expect("--correlation-id should parse");
                assert_eq!(id.as_str(), "feat-42_xyz");
            }
            _ => panic!("unexpected command"),
        }
    }

    /// `parse_correlation_id` runs `CorrelationId::try_new`, so the
    /// same character-class and length rules that gate the audit
    /// column also gate the CLI flag — no malformed value ever leaves
    /// the parser. A single representative bad byte is enough; the
    /// newtype's own tests exhaustively cover the class.
    #[test]
    fn agent_run_cli_rejects_invalid_correlation_id() {
        let err = match Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "codex",
            "--model",
            "gpt-5.4-mini",
            "--prompt",
            "fix it",
            "--correlation-id",
            "bad space",
        ]) {
            Ok(_) => panic!("expected clap to reject malformed --correlation-id"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--correlation-id"),
            "unexpected clap error: {err}"
        );
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
            "--model",
            "gpt-5.4-mini",
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
    fn agent_run_cli_rejects_missing_model() {
        let err = match Args::try_parse_from([
            "writ",
            "agent",
            "run",
            "--repo",
            "owner/repo",
            "--agent",
            "codex",
            "--prompt",
            "fix it",
        ]) {
            Ok(_) => panic!("expected clap to reject missing --model"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--model"),
            "unexpected clap error: {err}"
        );
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
            agent_model: "claude-test".into(),
            workspace,
            prompt: AgentPrompt::try_new("SECRET prompt").unwrap(),
            correlation_id: None,
        };

        let debug = format!("{msg:?}");

        assert!(!debug.contains("SECRET prompt"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn promote_reject_cli_requires_reason_flag() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reject",
            "11111111-1111-1111-1111-111111111111",
        ]) {
            Ok(_) => panic!("expected clap to reject missing --reason"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--reason"),
            "unexpected clap error: {err}"
        );
    }

    #[test]
    fn promote_reject_cli_parses_request_id_and_reason() {
        let args = Args::try_parse_from([
            "writ",
            "promote",
            "reject",
            "11111111-1111-1111-1111-111111111111",
            "--reason",
            "contains a secret",
        ])
        .unwrap();
        match args.cmd {
            Cmd::Promote {
                action: PromoteCmd::Reject { request_id, reason },
            } => {
                assert_eq!(request_id, "11111111-1111-1111-1111-111111111111");
                assert_eq!(reason, "contains a secret");
            }
            _ => panic!("unexpected command"),
        }
    }

    /// Clap must reject `promote reconcile` invocations that pass
    /// neither verdict flag — the `ArgGroup` declares the group
    /// required, so the parse should fail before the dispatch arm runs.
    #[test]
    fn promote_reconcile_cli_requires_one_verdict_flag() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
        ]) {
            Ok(_) => panic!("expected clap to require a verdict flag"),
            Err(error) => error,
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("--confirmed-applied")
                || rendered.contains("--confirmed-not-applied"),
            "unexpected clap error: {rendered}",
        );
    }

    /// Clap must reject invocations that pass both verdict flags — the
    /// `ArgGroup` is single-valued by default, so `multiple(false)`
    /// makes the two flags mutually exclusive.
    #[test]
    fn promote_reconcile_cli_rejects_both_verdict_flags() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-applied",
            "--confirmed-not-applied",
            "--new-app-tip",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--reason",
            "x",
            "--detail",
            "y",
        ]) {
            Ok(_) => panic!("expected clap to reject both verdict flags"),
            Err(error) => error,
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("cannot be used with"),
            "unexpected clap error: {rendered}",
        );
    }

    /// `--confirmed-applied` without `--new-app-tip` must fail at parse
    /// time; the `required_if_eq` predicate is what catches this before
    /// the daemon round-trip.
    #[test]
    fn promote_reconcile_cli_applied_requires_new_app_tip() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-applied",
            "--reason",
            "operator confirmed via GitHub UI",
        ]) {
            Ok(_) => panic!("expected clap to require --new-app-tip"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--new-app-tip"),
            "unexpected clap error: {err}",
        );
    }

    /// `--confirmed-applied` without `--reason` must fail at parse time
    /// even when `--new-app-tip` is present; the reason is the audit
    /// row's free-form text and the broker rejects empty values.
    #[test]
    fn promote_reconcile_cli_applied_requires_reason() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-applied",
            "--new-app-tip",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]) {
            Ok(_) => panic!("expected clap to require --reason"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--reason"),
            "unexpected clap error: {err}",
        );
    }

    /// A mistyped verdict — operator wrote `--confirmed-not-applied`
    /// but supplied applied-side flags — must fail at parse time
    /// rather than have clap silently discard the would-be applied
    /// SHA. For an audit-recording command this is a footgun: ignoring
    /// the flag would record a different decision than the operator
    /// intended.
    #[test]
    fn promote_reconcile_cli_rejects_new_app_tip_with_not_applied() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-not-applied",
            "--detail",
            "branch tip unchanged",
            "--new-app-tip",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]) {
            Ok(_) => panic!("expected clap to reject --new-app-tip with --confirmed-not-applied"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("cannot be used with"),
            "unexpected clap error: {err}",
        );
    }

    /// `--reason` paired with `--confirmed-not-applied` is the same
    /// contradiction shape — without `conflicts_with` the `--reason`
    /// would have been silently discarded in favour of `--detail`.
    #[test]
    fn promote_reconcile_cli_rejects_reason_with_not_applied() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-not-applied",
            "--detail",
            "branch tip unchanged",
            "--reason",
            "wrong field",
        ]) {
            Ok(_) => panic!("expected clap to reject --reason with --confirmed-not-applied"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("cannot be used with"),
            "unexpected clap error: {err}",
        );
    }

    /// `--detail` paired with `--confirmed-applied` is the inverse
    /// contradiction — without `conflicts_with` the `--detail` would
    /// have been silently discarded in favour of `--reason`.
    #[test]
    fn promote_reconcile_cli_rejects_detail_with_applied() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-applied",
            "--new-app-tip",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--reason",
            "manual confirmation",
            "--detail",
            "wrong field",
        ]) {
            Ok(_) => panic!("expected clap to reject --detail with --confirmed-applied"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("cannot be used with"),
            "unexpected clap error: {err}",
        );
    }

    /// `--confirmed-not-applied` without `--detail` must fail at parse
    /// time — symmetry with the applied-side `--reason` requirement.
    #[test]
    fn promote_reconcile_cli_not_applied_requires_detail() {
        let err = match Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-not-applied",
        ]) {
            Ok(_) => panic!("expected clap to require --detail"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--detail"),
            "unexpected clap error: {err}",
        );
    }

    /// Happy path: a fully-specified applied invocation parses into the
    /// expected enum shape with every field preserved verbatim.
    #[test]
    fn promote_reconcile_cli_applied_parses_full_flag_set() {
        let args = Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "11111111-1111-1111-1111-111111111111",
            "--confirmed-applied",
            "--new-app-tip",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--reason",
            "confirmed via GitHub UI after PostPatchFailure",
        ])
        .unwrap();
        match args.cmd {
            Cmd::Promote {
                action:
                    PromoteCmd::Reconcile {
                        request_id,
                        confirmed_applied,
                        confirmed_not_applied,
                        new_app_tip,
                        reason,
                        detail,
                    },
            } => {
                assert_eq!(request_id, "11111111-1111-1111-1111-111111111111");
                assert!(confirmed_applied);
                assert!(!confirmed_not_applied);
                assert_eq!(
                    new_app_tip.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                );
                assert_eq!(
                    reason.as_deref(),
                    Some("confirmed via GitHub UI after PostPatchFailure"),
                );
                assert_eq!(detail, None);
            }
            _ => panic!("unexpected command"),
        }
    }

    /// Happy path for the not-applied verdict; mirrors the applied
    /// parse test but with the inverse flag set.
    #[test]
    fn promote_reconcile_cli_not_applied_parses_full_flag_set() {
        let args = Args::try_parse_from([
            "writ",
            "promote",
            "reconcile",
            "22222222-2222-2222-2222-222222222222",
            "--confirmed-not-applied",
            "--detail",
            "branch tip unchanged on GitHub",
        ])
        .unwrap();
        match args.cmd {
            Cmd::Promote {
                action:
                    PromoteCmd::Reconcile {
                        request_id,
                        confirmed_applied,
                        confirmed_not_applied,
                        new_app_tip,
                        reason,
                        detail,
                    },
            } => {
                assert_eq!(request_id, "22222222-2222-2222-2222-222222222222");
                assert!(!confirmed_applied);
                assert!(confirmed_not_applied);
                assert_eq!(new_app_tip, None);
                assert_eq!(reason, None);
                assert_eq!(detail.as_deref(), Some("branch tip unchanged on GitHub"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_vm_build_image_cli_defaults_flake_to_dot_and_proof_to_false() {
        let args = Args::try_parse_from(["writ", "agent-vm", "build-image"]).unwrap();
        match args.cmd {
            Cmd::AgentVm {
                action:
                    AgentVmCmd::BuildImage {
                        proof,
                        guest_system,
                        flake,
                    },
            } => {
                assert!(!proof);
                assert_eq!(guest_system, None);
                assert_eq!(flake, ".");
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_vm_build_image_cli_accepts_proof_guest_system_and_flake() {
        let args = Args::try_parse_from([
            "writ",
            "agent-vm",
            "build-image",
            "--proof",
            "--guest-system",
            "x86_64-linux",
            "--flake",
            "/path/to/repo",
        ])
        .unwrap();
        match args.cmd {
            Cmd::AgentVm {
                action:
                    AgentVmCmd::BuildImage {
                        proof,
                        guest_system,
                        flake,
                    },
            } => {
                assert!(proof);
                assert_eq!(guest_system, Some(GuestSystemArg::X86_64Linux));
                assert_eq!(flake, "/path/to/repo");
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_vm_build_image_cli_rejects_unknown_guest_system() {
        let err = match Args::try_parse_from([
            "writ",
            "agent-vm",
            "build-image",
            "--guest-system",
            "riscv64-linux",
        ]) {
            Ok(_) => panic!("clap should reject unknown guest-system values"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--guest-system"),
            "unexpected clap error: {err}",
        );
    }
}
