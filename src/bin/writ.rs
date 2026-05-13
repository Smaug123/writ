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

use writ::agent_plan::{CorrelationId, Decider, DecisionOutcome, PlanId, Stage};
use writ::agent_run::AgentPrompt;
use writ::core::{
    AgentKind, CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, RequestId, SessionId,
};
use writ::protocol::{
    AgentVmSessionInfo, ClientMessage, PlanDetail, PlanSummary, RejectionReason, ServerMessage,
    StagedPushDetail, StagedPushSummary,
};
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
    /// Inspect VM-staged git pushes awaiting promotion review.
    Promote {
        #[command(subcommand)]
        action: PromoteCmd,
    },
    /// Inspect plans recorded by planner-stage agent runs.
    Plan {
        #[command(subcommand)]
        action: PlanCmd,
    },
}

#[derive(Subcommand)]
enum PlanCmd {
    /// List every plan the broker holds, optionally filtered by the
    /// planner run's correlation id. Bodies are not loaded — use
    /// `writ plan show <id>` for the body.
    List {
        /// Restrict the listing to plans whose planner run was tagged
        /// with this correlation id.
        #[arg(long, value_parser = parse_correlation_id)]
        correlation_id: Option<CorrelationId>,
    },
    /// Show one plan: metadata followed by the verbatim body.
    Show { plan_id: String },
    /// Record an operator decision on a plan. Exactly one of
    /// `--accept` or `--reject-restart` is required. The operator
    /// identity defaults to `cli:$USER` (or `cli:unknown` if unset);
    /// pass `--decider` to override the attribution stored in the
    /// audit row.
    #[command(group(ArgGroup::new("outcome").required(true).args(["accept", "reject_restart"])))]
    Decide {
        plan_id: String,
        /// Record the plan as accepted (review approves it).
        #[arg(long)]
        accept: bool,
        /// Record the plan as rejected for restart (review rejects
        /// the plan and the planner must run again).
        #[arg(long = "reject-restart")]
        reject_restart: bool,
        /// Override the decider attribution stored in the audit row.
        /// Defaults to `cli:$USER`.
        #[arg(long)]
        decider: Option<String>,
    },
}

#[derive(Subcommand)]
enum PromoteCmd {
    /// List every staged push the broker is holding for review.
    List,
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
        /// Role of this run in the plan/review/execute pipeline. The
        /// broker stamps it on the `agent_run.stage` audit column and
        /// the VM HTTP plan routes use it for per-stage authorisation.
        /// Defaults to `execute`, the historical (pre-pipeline) shape.
        #[arg(long, value_parser = parse_stage, default_value = "execute")]
        stage: Stage,
        /// Opaque caller-supplied id that ties this run to a wider
        /// task. Validated only as a safe id (`[A-Za-z0-9_-]`, 1..=64
        /// bytes); the broker never interprets the contents.
        #[arg(long, value_parser = parse_correlation_id)]
        correlation_id: Option<CorrelationId>,
        /// Plan this run is bound to read. Required for `--stage
        /// review` and for `--stage execute` runs that implement an
        /// accepted plan. Stamped on the `agent_run.read_plan_id`
        /// audit column and enforced by the VM HTTP plan-read route.
        #[arg(long, value_parser = parse_plan_id)]
        read_plan: Option<PlanId>,
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
                stage,
                correlation_id,
                read_plan,
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
                    stage,
                    correlation_id,
                    read_plan,
                )?;
            }
        },
        Cmd::Promote { action } => match action {
            PromoteCmd::List => {
                let msg = ClientMessage::ListStagedPushes {};
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
        },
        Cmd::Plan { action } => match action {
            PlanCmd::List { correlation_id } => {
                let msg = ClientMessage::ListPlans { correlation_id };
                match call(&socket_path, &msg)? {
                    ServerMessage::Plans { plans } => {
                        let mut out = std::io::stdout().lock();
                        write_plan_summaries(&mut out, &plans)?;
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            PlanCmd::Show { plan_id } => {
                let id: PlanId = plan_id
                    .parse()
                    .map_err(|e| format!("invalid plan ID: {e}"))?;
                let msg = ClientMessage::ShowPlan { plan_id: id };
                match call(&socket_path, &msg)? {
                    ServerMessage::Plan { plan } => {
                        let mut out = std::io::stdout().lock();
                        write_plan_detail(&mut out, &plan)?;
                    }
                    ServerMessage::UnknownPlan { plan_id } => {
                        return Err(format!("no plan with id {plan_id}").into());
                    }
                    ServerMessage::Error { message } => return Err(message.into()),
                    other => return Err(format!("unexpected response: {other:?}").into()),
                }
            }
            PlanCmd::Decide {
                plan_id,
                accept,
                reject_restart,
                decider,
            } => {
                let id: PlanId = plan_id
                    .parse()
                    .map_err(|e| format!("invalid plan ID: {e}"))?;
                let outcome = resolve_decision_outcome(accept, reject_restart);
                let decider = match decider {
                    Some(raw) => Decider::try_new(raw).map_err(|e| e.to_string())?,
                    None => {
                        let identity = capture_operator_identity();
                        Decider::try_new(format!("cli:{identity}"))
                            .map_err(|e| format!("invalid default decider: {e}"))?
                    }
                };
                let msg = ClientMessage::DecidePlan {
                    plan_id: id,
                    outcome,
                    decider,
                };
                match call(&socket_path, &msg)? {
                    ServerMessage::PlanDecided { plan_id } => {
                        println!("decided plan_id={plan_id} outcome={outcome}");
                    }
                    ServerMessage::UnknownPlan { plan_id } => {
                        return Err(format!("no plan with id {plan_id}").into());
                    }
                    ServerMessage::PlanAlreadyDecided { plan_id } => {
                        return Err(format!(
                            "plan {plan_id} already has an operator decision recorded",
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

fn parse_agent_kind(raw: &str) -> Result<AgentKind, String> {
    raw.parse::<AgentKind>().map_err(|err| err.to_string())
}

fn parse_correlation_id(raw: &str) -> Result<CorrelationId, String> {
    CorrelationId::try_new(raw).map_err(|err| err.to_string())
}

fn parse_stage(raw: &str) -> Result<Stage, String> {
    raw.parse::<Stage>().map_err(|err| err.to_string())
}

fn parse_plan_id(raw: &str) -> Result<PlanId, String> {
    raw.parse::<PlanId>().map_err(|err| err.to_string())
}

/// Read the operator identity the CLI will assert to the broker.
///
/// The local socket is the trust boundary, so this only needs to be a
/// stable, human-readable label. The pure mapping lives in
/// [`classify_operator_identity`] so it can be exercised in tests
/// without mutating the process environment — `std::env::set_var` is
/// unsafe under Rust 2024 and would race with Clap's env-aware
/// argument parsing in other unit tests.
fn capture_operator_identity() -> String {
    classify_operator_identity(std::env::var("USER").ok())
}

/// `$USER` is what every interactive shell sets; if it is missing or
/// empty (some CI containers drop it), record `"unknown"` rather than
/// failing the reject — the audit row should always land.
fn classify_operator_identity(user: Option<String>) -> String {
    match user {
        Some(value) if !value.is_empty() => value,
        _ => "unknown".to_string(),
    }
}

/// Map the parsed `--accept` / `--reject-restart` flags to a
/// [`DecisionOutcome`]. Clap's `ArgGroup` enforces exactly-one before
/// we get here, so the `(false, false)` and `(true, true)` cases are
/// unreachable in practice — they panic loudly rather than guess.
fn resolve_decision_outcome(accept: bool, reject_restart: bool) -> DecisionOutcome {
    match (accept, reject_restart) {
        (true, false) => DecisionOutcome::Accepted,
        (false, true) => DecisionOutcome::RejectedRestart,
        (false, false) | (true, true) => {
            unreachable!("clap ArgGroup enforces exactly one of --accept / --reject-restart")
        }
    }
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

#[allow(clippy::too_many_arguments)]
fn start_agent_run(
    socket_path: &Path,
    label: Option<String>,
    agent_kind: AgentKind,
    agent_model: String,
    workspace: AgentVmWorkspaceBootstrap,
    prompt: AgentPrompt,
    stage: Stage,
    correlation_id: Option<CorrelationId>,
    read_plan_id: Option<PlanId>,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = ClientMessage::StartAgentRun {
        label,
        agent_kind,
        agent_model,
        workspace,
        prompt,
        stage,
        correlation_id,
        read_plan_id,
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

fn write_staged_push_summaries(
    out: &mut dyn Write,
    pushes: &[StagedPushSummary],
) -> std::io::Result<()> {
    for (index, push) in pushes.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "push_request_id={}", push.push_request_id)?;
        writeln!(out, "repo={}", push.repo)?;
        writeln!(out, "branch={}", push.branch.as_str())?;
        // `expected_remote_head` absent is the "branch creation" signal —
        // surface it explicitly rather than silently omitting the line so
        // operators don't mistake a missing field for a missing OID.
        match &push.expected_remote_head {
            Some(oid) => writeln!(out, "expected_remote_head={}", oid.as_str())?,
            None => writeln!(out, "expected_remote_head=<branch_creation>")?,
        }
        writeln!(out, "new_head={}", push.new_head.as_str())?;
        writeln!(out, "staged_at={}", push.staged_at.as_millis())?;
    }
    Ok(())
}

fn write_staged_push_detail(out: &mut dyn Write, push: &StagedPushDetail) -> std::io::Result<()> {
    write_staged_push_summaries(out, std::slice::from_ref(&push.summary))?;
    writeln!(out, "bundle_bytes={}", push.bundle_bytes)?;
    writeln!(out, "session_id={}", push.audit.session_id)?;
    writeln!(out, "received_at={}", push.audit.received_at.as_millis())?;
    match push.audit.result {
        Some(result) => writeln!(out, "audit_result={}", result.as_str())?,
        // `<none>` matches the staged-vs-unknown distinction in the wire
        // protocol: an audit row exists but no outcome has been recorded.
        None => writeln!(out, "audit_result=<none>")?,
    }
    Ok(())
}

fn write_plan_summaries(out: &mut dyn Write, plans: &[PlanSummary]) -> std::io::Result<()> {
    for (index, plan) in plans.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "plan_id={}", plan.plan_id)?;
        writeln!(out, "agent_run_id={}", plan.agent_run_id)?;
        // Surface `<none>` rather than omitting the line so a missing
        // correlation_id is obvious in the listing.
        match &plan.correlation_id {
            Some(c) => writeln!(out, "correlation_id={}", c.as_str())?,
            None => writeln!(out, "correlation_id=<none>")?,
        }
        writeln!(out, "submitted_at={}", plan.submitted_at.as_millis())?;
        writeln!(out, "body_bytes={}", plan.body_bytes)?;
        writeln!(out, "body_sha256={}", plan.body_sha256)?;
    }
    Ok(())
}

fn write_plan_detail(out: &mut dyn Write, plan: &PlanDetail) -> std::io::Result<()> {
    write_plan_summaries(out, std::slice::from_ref(&plan.summary))?;
    // Body is a separate block so its newlines don't collide with the
    // key=value header. The blank line is the delimiter.
    writeln!(out)?;
    out.write_all(plan.body.as_bytes())?;
    // Ensure the body block is terminated even if the body itself
    // doesn't end with a newline (markdown often doesn't).
    if !plan.body.as_bytes().ends_with(b"\n") {
        writeln!(out)?;
    }
    // Reviews section: always emitted, even when empty, so the
    // section header doubles as a "no reviews yet" signal. The count
    // in the header mirrors the wire array length.
    writeln!(out)?;
    writeln!(out, "-- reviews ({}) --", plan.reviews.len())?;
    for review in &plan.reviews {
        writeln!(out)?;
        writeln!(out, "review_id={}", review.review_id)?;
        writeln!(out, "reviewer_run_id={}", review.reviewer_run_id)?;
        writeln!(out, "submitted_at={}", review.submitted_at.as_millis())?;
        writeln!(out, "verdict={}", review.verdict)?;
        // XML-style framing for multi-line feedback; an LLM consuming
        // the rendered output can locate the prose block by its
        // <feedback> tags rather than guessing where free-text ends.
        match &review.feedback {
            None => writeln!(out, "feedback=<none>")?,
            Some(feedback) => {
                writeln!(out, "<feedback>")?;
                out.write_all(feedback.as_bytes())?;
                if !feedback.as_bytes().ends_with(b"\n") {
                    writeln!(out)?;
                }
                writeln!(out, "</feedback>")?;
            }
        }
    }
    // Decision section: always emitted, surfacing `<none>` for a
    // plan that has not yet been decided so the section header stays
    // parallel with `reviews`.
    writeln!(out)?;
    writeln!(out, "-- decision --")?;
    match &plan.decision {
        None => writeln!(out, "outcome=<none>")?,
        Some(d) => {
            writeln!(out, "outcome={}", d.outcome)?;
            writeln!(out, "decided_at={}", d.decided_at.as_millis())?;
        }
    }
    Ok(())
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
                        stage,
                        correlation_id,
                        read_plan,
                        ..
                    },
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(agent, AgentKind::Claude);
                assert_eq!(prompt, "fix the failing test");
                assert_eq!(model, "claude-test");
                assert_eq!(warm, WorkspaceWarmArg::Sources);
                assert_eq!(stage, Stage::Execute);
                assert!(correlation_id.is_none());
                assert!(read_plan.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_run_cli_defaults_stage_to_execute() {
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
            "p",
        ])
        .unwrap();
        match args.cmd {
            Cmd::Agent {
                action: AgentCmd::Run { stage, .. },
            } => assert_eq!(stage, Stage::Execute),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn agent_run_cli_accepts_stage_flag_for_every_stage() {
        for (raw, expected) in [
            ("plan", Stage::Plan),
            ("review", Stage::Review),
            ("execute", Stage::Execute),
        ] {
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
                "p",
                "--stage",
                raw,
            ])
            .unwrap();
            match args.cmd {
                Cmd::Agent {
                    action: AgentCmd::Run { stage, .. },
                } => assert_eq!(stage, expected, "raw {raw}"),
                _ => panic!("unexpected command"),
            }
        }
    }

    /// Malformed stages must fail at clap rather than reach the broker,
    /// so the audit-log CHECK is never the line of defence. The
    /// `Stage::from_str` test in `agent_plan` already covers the
    /// character class; here we only verify the CLI surfaces the
    /// rejection on the `--stage` flag.
    #[test]
    fn agent_run_cli_rejects_unknown_stage() {
        let err = match Args::try_parse_from([
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
            "p",
            "--stage",
            "planner",
        ]) {
            Ok(_) => panic!("expected clap to reject malformed --stage"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--stage"),
            "unexpected clap error: {err}",
        );
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

    /// `--read-plan` is the CLI surface for the
    /// `agent_run.read_plan_id` audit column and the VM HTTP
    /// plan-read authorisation gate; the parser must accept a
    /// well-formed UUID and surface it as `Some` on the parsed
    /// command.
    #[test]
    fn agent_run_cli_accepts_read_plan_flag() {
        let plan_uuid = "f1f1f1f1-0000-0000-0000-000000000001";
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
            "implement plan",
            "--stage",
            "execute",
            "--read-plan",
            plan_uuid,
        ])
        .unwrap();

        match args.cmd {
            Cmd::Agent {
                action: AgentCmd::Run { read_plan, .. },
            } => {
                let id = read_plan.expect("--read-plan should parse");
                assert_eq!(id.as_uuid().to_string(), plan_uuid);
            }
            _ => panic!("unexpected command"),
        }
    }

    /// `parse_plan_id` runs the same `PlanId::from_str` (UUID parse)
    /// that the audit DAO uses, so any non-UUID payload is a clap
    /// error rather than a broker rejection — the parse-don't-
    /// validate boundary lives at the CLI.
    #[test]
    fn agent_run_cli_rejects_malformed_read_plan() {
        let err = match Args::try_parse_from([
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
            "p",
            "--read-plan",
            "not-a-uuid",
        ]) {
            Ok(_) => panic!("expected clap to reject malformed --read-plan"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("--read-plan"),
            "unexpected clap error: {err}",
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
            agent_model: "claude-test".into(),
            workspace,
            prompt: AgentPrompt::try_new("SECRET prompt").unwrap(),
            stage: Stage::Execute,
            correlation_id: None,
            read_plan_id: None,
        };

        let debug = format!("{msg:?}");

        assert!(!debug.contains("SECRET prompt"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    fn staged_summary_fixture(
        request_id: RequestId,
        branch: &str,
        expected_remote_head: Option<&str>,
        new_head: &str,
        staged_at_ms: i64,
    ) -> StagedPushSummary {
        StagedPushSummary {
            push_request_id: request_id,
            repo: "owner/repo".parse().unwrap(),
            branch: branch.parse().unwrap(),
            expected_remote_head: expected_remote_head.map(|s| s.parse().unwrap()),
            new_head: new_head.parse().unwrap(),
            staged_at: writ::core::UnixMillis::from_millis(staged_at_ms),
        }
    }

    #[test]
    fn staged_push_list_output_is_key_value_separated_by_blank_lines() {
        let id_a: RequestId = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let id_b: RequestId = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let pushes = vec![
            staged_summary_fixture(
                id_a,
                "feature/x",
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1_700_000_001_000,
            ),
            staged_summary_fixture(
                id_b,
                "feature/y",
                None,
                "cccccccccccccccccccccccccccccccccccccccc",
                1_700_000_002_000,
            ),
        ];
        let mut out = Vec::new();

        write_staged_push_summaries(&mut out, &pushes).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "push_request_id=11111111-1111-1111-1111-111111111111\n",
                "repo=owner/repo\n",
                "branch=feature/x\n",
                "expected_remote_head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                "new_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "staged_at=1700000001000\n",
                "\n",
                "push_request_id=22222222-2222-2222-2222-222222222222\n",
                "repo=owner/repo\n",
                "branch=feature/y\n",
                "expected_remote_head=<branch_creation>\n",
                "new_head=cccccccccccccccccccccccccccccccccccccccc\n",
                "staged_at=1700000002000\n",
            )
        );
    }

    #[test]
    fn staged_push_detail_output_appends_bundle_and_audit_fields() {
        let request_id: RequestId = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session_id: SessionId = "44444444-4444-4444-4444-444444444444".parse().unwrap();
        let summary = staged_summary_fixture(
            request_id,
            "main",
            Some("dddddddddddddddddddddddddddddddddddddddd"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            1_700_000_500_000,
        );
        let detail = StagedPushDetail {
            summary,
            bundle_bytes: 4096,
            audit: writ::protocol::StagedPushAuditView {
                session_id,
                received_at: writ::core::UnixMillis::from_millis(1_700_000_500_250),
                result: Some(writ::audit::GitPushOutcomeResult::Staged),
            },
        };
        let mut out = Vec::new();

        write_staged_push_detail(&mut out, &detail).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "push_request_id=33333333-3333-3333-3333-333333333333\n",
                "repo=owner/repo\n",
                "branch=main\n",
                "expected_remote_head=dddddddddddddddddddddddddddddddddddddddd\n",
                "new_head=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n",
                "staged_at=1700000500000\n",
                "bundle_bytes=4096\n",
                "session_id=44444444-4444-4444-4444-444444444444\n",
                "received_at=1700000500250\n",
                "audit_result=staged\n",
            )
        );
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

    /// Pins the operator-identity mapping: a set value flows through
    /// verbatim; missing or empty falls back to `"unknown"` so the
    /// audit row always lands. Tested on the pure helper so the suite
    /// never mutates `USER` at runtime — `set_var` would race with
    /// Clap's env-aware parsers in other parallel tests.
    #[test]
    fn classify_operator_identity_maps_user_env_with_unknown_fallback() {
        assert_eq!(classify_operator_identity(Some("alice".into())), "alice");
        assert_eq!(classify_operator_identity(Some(String::new())), "unknown");
        assert_eq!(classify_operator_identity(None), "unknown");
    }

    /// An audit row that exists without an outcome row prints as
    /// `<none>` rather than being suppressed: an operator triaging a
    /// stuck staged push wants to see the missing outcome explicitly.
    #[test]
    fn staged_push_detail_output_renders_missing_audit_outcome_as_none() {
        let request_id: RequestId = "55555555-5555-5555-5555-555555555555".parse().unwrap();
        let session_id: SessionId = "66666666-6666-6666-6666-666666666666".parse().unwrap();
        let detail = StagedPushDetail {
            summary: staged_summary_fixture(
                request_id,
                "main",
                None,
                "ffffffffffffffffffffffffffffffffffffffff",
                1,
            ),
            bundle_bytes: 0,
            audit: writ::protocol::StagedPushAuditView {
                session_id,
                received_at: writ::core::UnixMillis::from_millis(2),
                result: None,
            },
        };
        let mut out = Vec::new();

        write_staged_push_detail(&mut out, &detail).unwrap();

        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("audit_result=<none>\n"), "{rendered}");
        assert!(
            rendered.contains("expected_remote_head=<branch_creation>\n"),
            "{rendered}",
        );
    }

    #[test]
    fn plan_list_cli_accepts_correlation_id_filter() {
        let args =
            Args::try_parse_from(["writ", "plan", "list", "--correlation-id", "feat-42_xyz"])
                .unwrap();
        match args.cmd {
            Cmd::Plan {
                action: PlanCmd::List { correlation_id },
            } => {
                let id = correlation_id.expect("--correlation-id should parse");
                assert_eq!(id.as_str(), "feat-42_xyz");
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn plan_list_cli_without_correlation_id_filter_is_none() {
        let args = Args::try_parse_from(["writ", "plan", "list"]).unwrap();
        match args.cmd {
            Cmd::Plan {
                action: PlanCmd::List { correlation_id },
            } => {
                assert!(correlation_id.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn plan_list_cli_rejects_invalid_correlation_id() {
        let err =
            match Args::try_parse_from(["writ", "plan", "list", "--correlation-id", "bad space"]) {
                Ok(_) => panic!("expected clap to reject malformed --correlation-id"),
                Err(error) => error,
            };
        let rendered = err.to_string();
        assert!(rendered.contains("correlation id"), "{rendered}");
    }

    #[test]
    fn plan_show_cli_accepts_plan_id() {
        let id = "f1f1f1f1-0000-0000-0000-000000000001";
        let args = Args::try_parse_from(["writ", "plan", "show", id]).unwrap();
        match args.cmd {
            Cmd::Plan {
                action: PlanCmd::Show { plan_id },
            } => assert_eq!(plan_id, id),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn plan_decide_cli_accepts_accept_flag() {
        let id = "f1f1f1f1-0000-0000-0000-000000000001";
        let args = Args::try_parse_from(["writ", "plan", "decide", id, "--accept"]).unwrap();
        match args.cmd {
            Cmd::Plan {
                action:
                    PlanCmd::Decide {
                        plan_id,
                        accept,
                        reject_restart,
                        decider,
                    },
            } => {
                assert_eq!(plan_id, id);
                assert!(accept);
                assert!(!reject_restart);
                assert!(decider.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn plan_decide_cli_accepts_reject_restart_flag() {
        let id = "f1f1f1f1-0000-0000-0000-000000000001";
        let args =
            Args::try_parse_from(["writ", "plan", "decide", id, "--reject-restart"]).unwrap();
        match args.cmd {
            Cmd::Plan {
                action:
                    PlanCmd::Decide {
                        plan_id,
                        accept,
                        reject_restart,
                        decider,
                    },
            } => {
                assert_eq!(plan_id, id);
                assert!(!accept);
                assert!(reject_restart);
                assert!(decider.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn plan_decide_cli_accepts_decider_override() {
        let id = "f1f1f1f1-0000-0000-0000-000000000001";
        let args = Args::try_parse_from([
            "writ",
            "plan",
            "decide",
            id,
            "--accept",
            "--decider",
            "agent:run-42",
        ])
        .unwrap();
        match args.cmd {
            Cmd::Plan {
                action: PlanCmd::Decide { decider, .. },
            } => assert_eq!(decider.as_deref(), Some("agent:run-42")),
            _ => panic!("unexpected command"),
        }
    }

    /// Clap's `ArgGroup` on the outcome flags must reject both
    /// invocations that omit the outcome and invocations that pass
    /// both — neither is meaningful and silently picking one would
    /// hide an operator typo.
    #[test]
    fn plan_decide_cli_requires_exactly_one_outcome_flag() {
        let id = "f1f1f1f1-0000-0000-0000-000000000001";

        let missing = Args::try_parse_from(["writ", "plan", "decide", id]);
        assert!(missing.is_err(), "expected clap to reject missing outcome");

        let both =
            Args::try_parse_from(["writ", "plan", "decide", id, "--accept", "--reject-restart"]);
        assert!(both.is_err(), "expected clap to reject both outcomes");
    }

    #[test]
    fn resolve_decision_outcome_maps_each_flag() {
        assert_eq!(
            resolve_decision_outcome(true, false),
            DecisionOutcome::Accepted,
        );
        assert_eq!(
            resolve_decision_outcome(false, true),
            DecisionOutcome::RejectedRestart,
        );
    }

    fn sample_plan_summary_for_cli(with_correlation: bool) -> PlanSummary {
        PlanSummary {
            plan_id: "f1f1f1f1-0000-0000-0000-000000000001".parse().unwrap(),
            agent_run_id: "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap(),
            correlation_id: if with_correlation {
                Some(CorrelationId::try_new("feat-42_xyz").unwrap())
            } else {
                None
            },
            submitted_at: writ::core::UnixMillis::from_millis(1_700_000_000_000),
            body_sha256: "a".repeat(64),
            body_bytes: 42,
        }
    }

    #[test]
    fn plan_summaries_render_key_value_lines_with_blank_lines_between_records() {
        let plans = vec![
            sample_plan_summary_for_cli(true),
            sample_plan_summary_for_cli(false),
        ];
        let mut out = Vec::new();
        write_plan_summaries(&mut out, &plans).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert_eq!(
            rendered,
            concat!(
                "plan_id=f1f1f1f1-0000-0000-0000-000000000001\n",
                "agent_run_id=f2f2f2f2-0000-0000-0000-000000000001\n",
                "correlation_id=feat-42_xyz\n",
                "submitted_at=1700000000000\n",
                "body_bytes=42\n",
                "body_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                "\n",
                "plan_id=f1f1f1f1-0000-0000-0000-000000000001\n",
                "agent_run_id=f2f2f2f2-0000-0000-0000-000000000001\n",
                "correlation_id=<none>\n",
                "submitted_at=1700000000000\n",
                "body_bytes=42\n",
                "body_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            )
        );
    }

    #[test]
    fn plan_detail_renders_summary_then_body_separated_by_blank_line() {
        let body = writ::agent_plan::PlanBody::try_new("# Plan\n\nStep 1.\n").unwrap();
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(true),
            body,
            reviews: vec![],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        // The summary block, a blank line, then the body verbatim,
        // then a blank line before the reviews section.
        let body_offset = rendered.find("# Plan").expect("body present");
        assert!(rendered[..body_offset].ends_with("\n\n"), "{rendered}");
        assert!(
            rendered[body_offset..].starts_with("# Plan\n\nStep 1.\n\n-- reviews"),
            "{rendered}",
        );
    }

    /// A body that doesn't terminate in a newline still ends with one
    /// when written so the reviews section header lands on its own line.
    #[test]
    fn plan_detail_terminates_unterminated_body_with_newline() {
        let body = writ::agent_plan::PlanBody::try_new("trailing").unwrap();
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(true),
            body,
            reviews: vec![],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("trailing\n\n-- reviews"), "{rendered}");
    }

    fn sample_review_view_for_cli(
        review_id_hex: &str,
        reviewer_run_hex: &str,
        submitted_at_ms: i64,
        verdict: writ::agent_plan::Verdict,
        feedback: Option<writ::agent_plan::PlanFeedback>,
    ) -> writ::protocol::PlanReviewView {
        writ::protocol::PlanReviewView {
            review_id: review_id_hex.parse().unwrap(),
            reviewer_run_id: reviewer_run_hex.parse().unwrap(),
            submitted_at: writ::core::UnixMillis::from_millis(submitted_at_ms),
            verdict,
            feedback,
        }
    }

    /// An empty reviews vec still emits the section header — the
    /// rendered output is a discoverable surface for operators, and
    /// the empty header doubles as a "no reviews yet" signal that
    /// matches the wire (always-emit-[]) shape.
    #[test]
    fn plan_detail_renders_empty_reviews_block_with_zero_count() {
        let body = writ::agent_plan::PlanBody::try_new("# Plan\n").unwrap();
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(false),
            body,
            reviews: vec![],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("-- reviews (0) --\n"),
            "expected zero-review header, got {rendered}",
        );
        // No review records leak through.
        assert!(!rendered.contains("review_id="), "{rendered}");
        assert!(!rendered.contains("reviewer_run_id="), "{rendered}");
    }

    /// Reviews render in input order with key=value lines for the
    /// scalar fields and an XML-framed prose block for multi-line
    /// feedback. The framing lets an LLM consuming the output
    /// locate the prose block by the `<feedback>` tags rather than
    /// guessing where free-text ends.
    #[test]
    fn plan_detail_renders_reviews_in_order_with_xml_framed_feedback() {
        let body = writ::agent_plan::PlanBody::try_new("# Plan\n").unwrap();
        let feedback =
            writ::agent_plan::PlanFeedback::try_new("Two concerns:\n1. naming\n2. ordering")
                .unwrap();
        let first = sample_review_view_for_cli(
            "f3f3f3f3-0000-0000-0000-000000000001",
            "f4f4f4f4-0000-0000-0000-000000000001",
            1_700_000_300_000,
            writ::agent_plan::Verdict::RequestChanges,
            Some(feedback),
        );
        let second = sample_review_view_for_cli(
            "f3f3f3f3-0000-0000-0000-000000000002",
            "f4f4f4f4-0000-0000-0000-000000000002",
            1_700_000_400_000,
            writ::agent_plan::Verdict::Approve,
            None,
        );
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(false),
            body,
            reviews: vec![first, second],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("-- reviews (2) --\n"), "{rendered}");
        let first_block = concat!(
            "review_id=f3f3f3f3-0000-0000-0000-000000000001\n",
            "reviewer_run_id=f4f4f4f4-0000-0000-0000-000000000001\n",
            "submitted_at=1700000300000\n",
            "verdict=request_changes\n",
            "<feedback>\n",
            "Two concerns:\n1. naming\n2. ordering\n",
            "</feedback>\n",
        );
        let second_block = concat!(
            "review_id=f3f3f3f3-0000-0000-0000-000000000002\n",
            "reviewer_run_id=f4f4f4f4-0000-0000-0000-000000000002\n",
            "submitted_at=1700000400000\n",
            "verdict=approve\n",
            "feedback=<none>\n",
        );
        let first_pos = rendered
            .find(first_block)
            .unwrap_or_else(|| panic!("first review block missing in {rendered}"));
        let second_pos = rendered
            .find(second_block)
            .unwrap_or_else(|| panic!("second review block missing in {rendered}"));
        assert!(
            first_pos < second_pos,
            "reviews must render in input order, got {rendered}",
        );
    }

    /// Feedback that already ends in a newline must not gain a second
    /// one before the closing tag — the renderer's terminator logic
    /// is conditional on the body's existing tail.
    #[test]
    fn plan_detail_does_not_double_terminate_feedback_that_ends_with_newline() {
        let body = writ::agent_plan::PlanBody::try_new("# Plan\n").unwrap();
        let feedback = writ::agent_plan::PlanFeedback::try_new("Done.\n").unwrap();
        let review = sample_review_view_for_cli(
            "f3f3f3f3-0000-0000-0000-000000000001",
            "f4f4f4f4-0000-0000-0000-000000000001",
            1_700_000_300_000,
            writ::agent_plan::Verdict::Approve,
            Some(feedback),
        );
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(false),
            body,
            reviews: vec![review],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("<feedback>\nDone.\n</feedback>\n"),
            "feedback framing must not introduce a blank line, got {rendered}",
        );
    }

    /// A plan with no decision still emits the `-- decision --`
    /// header so the section is visible to operators; the body shows
    /// `outcome=<none>` parallel with how `correlation_id=<none>`
    /// surfaces a missing summary field.
    #[test]
    fn plan_detail_renders_decision_none_as_placeholder() {
        let body = writ::agent_plan::PlanBody::try_new("# Plan\n").unwrap();
        let detail = PlanDetail {
            summary: sample_plan_summary_for_cli(false),
            body,
            reviews: vec![],
            decision: None,
        };
        let mut out = Vec::new();
        write_plan_detail(&mut out, &detail).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("-- decision --\noutcome=<none>\n"),
            "{rendered}",
        );
        assert!(!rendered.contains("decided_at="), "{rendered}");
    }

    /// Both outcomes render the same shape — outcome and decided_at
    /// key=value lines — so operators can rely on the section's
    /// structure regardless of the verdict.
    #[test]
    fn plan_detail_renders_decision_block_with_outcome_and_decided_at() {
        for (outcome, expected) in [
            (DecisionOutcome::Accepted, "outcome=accepted\n"),
            (
                DecisionOutcome::RejectedRestart,
                "outcome=rejected_restart\n",
            ),
        ] {
            let body = writ::agent_plan::PlanBody::try_new("# Plan\n").unwrap();
            let detail = PlanDetail {
                summary: sample_plan_summary_for_cli(false),
                body,
                reviews: vec![],
                decision: Some(writ::agent_plan::DecisionView {
                    outcome,
                    decided_at: writ::core::UnixMillis::from_millis(1_700_000_500_000),
                }),
            };
            let mut out = Vec::new();
            write_plan_detail(&mut out, &detail).unwrap();
            let rendered = String::from_utf8(out).unwrap();
            let expected_block = format!("-- decision --\n{expected}decided_at=1700000500000\n",);
            assert!(
                rendered.contains(&expected_block),
                "expected decision block {expected_block:?} in {rendered}",
            );
        }
    }
}
