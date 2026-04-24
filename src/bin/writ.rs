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

use writ::core::{CapabilityRequest, GitHubAccess, GitHubRequest, RepoRef, SessionId};
use writ::protocol::{ClientMessage, ServerMessage};
use writ::server::default_socket_path;

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
        Cmd::OpenSession { label, model } => {
            let msg = ClientMessage::OpenSession {
                label,
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
    }
    Ok(())
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

fn call(
    socket_path: &Path,
    msg: &ClientMessage,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("cannot connect to {}: {e}", socket_path.display()))?;

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
