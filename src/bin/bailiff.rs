//! `bailiff` — the workflow orchestrator that drives plan submission
//! (and, in later slices, review/execute) on top of writ's `RunAgent`
//! RPC. See `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! Slice C3 introduces the first operator-facing verb,
//! `bailiff plan submit`: open a writ session, run the planner agent,
//! verify writ's signed envelope, and persist a
//! [`writ::bailiff_plan_note::PlanNote`] in bailiff's own bare repo.
//! The workflow itself lives in
//! [`writ::bailiff_plan_submit::submit_plan`]; this binary is the
//! thin CLI layer that resolves paths, parses flags, and prints the
//! plan id on success.
//!
//! Paths default to the same XDG convention `docs/design/broker.md`
//! pins for writ, mirrored under `bailiff/`:
//! `$XDG_DATA_HOME/bailiff/repo` for bailiff's bare repo and
//! `$XDG_DATA_HOME/writ/repo` for the writ-owned repo bailiff
//! fetches from. `--bailiff-repo` and `--writ-repo` override either.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{ArgGroup, Parser, Subcommand};
use tokio::sync::Mutex as AsyncMutex;

use writ::agent_run::AgentPrompt;
use writ::bailiff_decision::{Decider, Decision};
use writ::bailiff_plan_note::{DecisionNote, PlanId};
use writ::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
use writ::bailiff_plan_write::{WriteDecisionNoteError, write_decision_note};
use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::server::default_socket_path;
use writ::writ_client::WritClient;

/// Notes ref writ writes the signed envelope to. Bailiff is the
/// consumer here: it names the ref in `RunAgent` and reads from the
/// same ref under writ's namespace after fetch. The slice-B4 pinned
/// design fixes this as the v1 convention; bumping it is a coordinated
/// `writ/v1` → `writ/v2` change handled in a future slice.
const WRIT_OUTPUT_REF: &str = "refs/notes/writ/v1/agent-outputs";

#[derive(Parser)]
#[command(name = "bailiff", about = "bailiff workflow orchestrator")]
struct Args {
    /// Path to the writ broker Unix socket. Falls back to
    /// `default_socket_path()` if neither the flag nor `WRIT_SOCKET`
    /// is set, matching the writ CLI's resolution order.
    #[arg(long, env = "WRIT_SOCKET")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Plan workflows (submit today; review/decide/implement land in
    /// later slices).
    Plan {
        #[command(subcommand)]
        action: PlanCmd,
    },
}

#[derive(Subcommand)]
enum PlanCmd {
    /// Submit a new plan: open a writ session, run the planner
    /// agent, verify the signed envelope, and persist the
    /// bailiff-side plan note. Prints the plan id to stdout on
    /// success.
    Submit {
        /// File containing the planner prompt. The bytes are read
        /// once and passed to writ verbatim; size validation
        /// happens at the boundary via [`AgentPrompt::try_new`].
        #[arg(long)]
        prompt_file: PathBuf,
        /// Repository the planner is allowed to read, in
        /// `owner/name` form. Today bailiff grants a single
        /// `WorkspaceRead` capability on this repo; future slices
        /// may broaden the set.
        #[arg(long)]
        repo: String,
        /// Path to bailiff's bare git repo. Defaults to
        /// `$XDG_DATA_HOME/bailiff/repo` (or
        /// `~/.local/share/bailiff/repo` if `XDG_DATA_HOME` is
        /// unset). Created on first use via
        /// [`NotesRepo::init_or_open`].
        #[arg(long)]
        bailiff_repo: Option<PathBuf>,
        /// Path to writ's bare git repo. Defaults to
        /// `$XDG_DATA_HOME/writ/repo`. Bailiff fetches writ's
        /// notes namespace from this path; it does not write to it.
        #[arg(long)]
        writ_repo: Option<PathBuf>,
        /// OpenSSH `allowed_signers` file enumerating which writ
        /// signing keys bailiff will accept envelopes from.
        /// Bootstrap is "writ prints its key fingerprint on first
        /// run; operator adds it here."
        #[arg(long)]
        writ_allowed_signers: PathBuf,
        /// Optional bailiff plan id; one is generated if omitted.
        /// Surfaced for replay and for test scripting; production
        /// callers normally let bailiff allocate it.
        #[arg(long)]
        plan_id: Option<PlanId>,
        /// Opaque tag recorded verbatim on writ's audit row and on
        /// the bailiff-side plan note. Defaults to `"plan-submit"`.
        #[arg(long, default_value = "plan-submit")]
        purpose: String,
        /// Human-readable session label stored in writ's audit
        /// log. Informational only; useful for cross-referencing
        /// when an operator inspects writ's session table.
        #[arg(long)]
        label: Option<String>,
        /// Coarse agent identity passed to writ's `OpenSession`.
        /// Required because writ refuses to open a session without
        /// one when a GitHub-app registry is configured. Defaults
        /// to `claude` to match the common-case planner identity.
        #[arg(long, default_value = "claude", value_parser = parse_agent_kind)]
        agent: AgentKind,
        /// Optional model identifier stored on writ's session row.
        #[arg(long)]
        model: Option<String>,
    },
    /// Record an operator verdict on a previously-submitted plan.
    /// Exactly one of `--accept` / `--reject` is required.
    ///
    /// D1.3 deliberately decoupled the decision write from submission
    /// presence — the verb succeeds even when no submission note
    /// exists yet under the plan's ref. The only typed failure is
    /// `DecisionAlreadyRecorded` (a duplicate decide for the same
    /// plan id); the read-side `read_decision_note` is the predicate
    /// future acceptance gates consult.
    #[command(group(
        ArgGroup::new("decide_outcome")
            .required(true)
            .args(["accept", "reject"]),
    ))]
    Decide {
        /// Plan to rule on. Must parse as the canonical UUID form
        /// `PlanId` prints.
        #[arg(long)]
        plan_id: PlanId,
        /// Record the plan as accepted. Mutually exclusive with
        /// `--reject`; clap's `ArgGroup` enforces exactly-one.
        #[arg(long)]
        accept: bool,
        /// Record the plan as rejected. The plan is dead from
        /// bailiff's perspective; the operator decides what (if
        /// anything) to do next. No auto-restart.
        #[arg(long)]
        reject: bool,
        /// Override the decider attribution recorded on the note.
        /// Defaults to `cli:$USER`; the verb fails if neither flag
        /// nor `$USER` is set — unlike writ's legacy `plan decide`
        /// (which falls back to `cli:unknown`), bailiff treats an
        /// unattributable verdict as an operator-config bug rather
        /// than silently degrading audit value. Slice G deletes
        /// writ's legacy verb so the divergence is temporary.
        #[arg(long)]
        decider: Option<String>,
        /// Path to bailiff's bare git repo. Defaults to
        /// `$XDG_DATA_HOME/bailiff/repo` (or
        /// `~/.local/share/bailiff/repo` if `XDG_DATA_HOME` is
        /// unset). Created on first use via
        /// [`NotesRepo::init_or_open`].
        #[arg(long)]
        bailiff_repo: Option<PathBuf>,
    },
}

fn parse_agent_kind(raw: &str) -> Result<AgentKind, String> {
    raw.parse::<AgentKind>().map_err(|e| e.to_string())
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(dispatch(args.cmd, socket_path))
}

async fn dispatch(cmd: Cmd, socket_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Cmd::Plan { action } => match action {
            PlanCmd::Submit {
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                plan_id,
                purpose,
                label,
                agent,
                model,
            } => {
                plan_submit(
                    socket_path,
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    plan_id,
                    purpose,
                    label,
                    agent,
                    model,
                )
                .await
            }
            PlanCmd::Decide {
                plan_id,
                accept,
                reject,
                decider,
                bailiff_repo,
            } => plan_decide(plan_id, accept, reject, decider, bailiff_repo).await,
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn plan_submit(
    socket_path: PathBuf,
    prompt_file: PathBuf,
    repo: String,
    bailiff_repo: Option<PathBuf>,
    writ_repo: Option<PathBuf>,
    writ_allowed_signers: PathBuf,
    plan_id: Option<PlanId>,
    purpose: String,
    label: Option<String>,
    agent: AgentKind,
    model: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve and read every on-disk input before opening any RPCs —
    // a bad prompt path or malformed allowed-signers file should
    // surface before bailiff makes a side-effecting writ call.
    let prompt_bytes = std::fs::read(&prompt_file)
        .map_err(|e| format!("reading prompt file {}: {e}", prompt_file.display()))?;
    let prompt_str = String::from_utf8(prompt_bytes).map_err(|e| {
        format!(
            "prompt file {} is not valid UTF-8: {e}",
            prompt_file.display()
        )
    })?;
    let prompt = AgentPrompt::try_new(prompt_str)
        .map_err(|e| format!("prompt from {} rejected: {e}", prompt_file.display()))?;

    let repo: RepoRef = repo
        .parse()
        .map_err(|e| format!("--repo {repo:?} is not 'owner/name': {e}"))?;

    let bailiff_repo_path = bailiff_repo.unwrap_or_else(default_bailiff_repo_path);
    let writ_repo_path = writ_repo.unwrap_or_else(default_writ_repo_path);

    let allowed_signers_text = std::fs::read_to_string(&writ_allowed_signers).map_err(|e| {
        format!(
            "reading writ allowed-signers file {}: {e}",
            writ_allowed_signers.display()
        )
    })?;
    let allowed = AllowedSigners::from_openssh_lines(&allowed_signers_text).map_err(|e| {
        format!(
            "parsing writ allowed-signers file {}: {e}",
            writ_allowed_signers.display()
        )
    })?;

    // `NotesRepo::init_or_open` shells out to git; do it on a
    // blocking thread so the runtime stays responsive. The
    // `bailiff_repo_path` is moved into the closure so the spawn
    // doesn't have to handle a lifetime.
    let bailiff_repo_path_for_init = bailiff_repo_path.clone();
    let bailiff =
        tokio::task::spawn_blocking(move || NotesRepo::init_or_open(bailiff_repo_path_for_init))
            .await
            .map_err(|e| format!("bailiff-repo init task failed: {e}"))?
            .map_err(|e| {
                format!(
                    "opening bailiff repo at {}: {e}",
                    bailiff_repo_path.display()
                )
            })?;
    let bailiff = Arc::new(AsyncMutex::new(bailiff));

    let plan_id = plan_id.unwrap_or_else(PlanId::new);
    let writ_output_ref =
        NotesRef::try_new(WRIT_OUTPUT_REF).expect("WRIT_OUTPUT_REF is a static well-formed ref");

    let inputs = SubmitPlanInputs {
        prompt,
        capabilities: vec![CapabilitySet::WorkspaceRead { repo }],
        purpose,
        writ_output_ref,
        session_label: label,
        session_agent_kind: Some(agent),
        session_agent_model: model,
        plan_id,
    };

    let client = WritClient::new(&socket_path);
    let outcome = submit_plan(&client, bailiff, &writ_repo_path, allowed, inputs).await?;
    println!("{}", outcome.plan_id);
    Ok(())
}

/// `$XDG_DATA_HOME/bailiff/repo` (or `~/.local/share/bailiff/repo`
/// if `XDG_DATA_HOME` is unset). Mirrors writ's own
/// `default_audit_db_path` / `default_secret_store_path` shape;
/// see `docs/plans/2026-05-14-bailiff-split.md` slice B4.
fn default_bailiff_repo_path() -> PathBuf {
    xdg_data_subdir("bailiff/repo")
}

/// `$XDG_DATA_HOME/writ/repo`. Bailiff resolves writ's repo
/// location from its own copy of the convention so there is no
/// duplicate-config edit when moving the path (slice B4 pin).
///
/// **Must agree with `writ::config::default_notes_repo_path`** —
/// writd stores RunAgent envelopes at the same location bailiff
/// fetches from. The two are independent functions because the
/// bailiff binary doesn't depend on writd's `config` module.
fn default_writ_repo_path() -> PathBuf {
    xdg_data_subdir("writ/repo")
}

async fn plan_decide(
    plan_id: PlanId,
    accept: bool,
    reject: bool,
    decider: Option<String>,
    bailiff_repo: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = resolve_decision_outcome(accept, reject);
    let user_env = std::env::var("USER").ok().filter(|s| !s.is_empty());
    let decider = resolve_decider(decider, user_env)?;
    let bailiff_repo_path = bailiff_repo.unwrap_or_else(default_bailiff_repo_path);

    let note = DecisionNote {
        plan_id,
        outcome,
        decider,
        decided_at: UnixMillis::now(),
    };

    // Both `init_or_open` and `write_decision_note` shell out to git;
    // run them on a blocking thread so the runtime stays responsive.
    let bailiff_repo_path_for_init = bailiff_repo_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let repo = NotesRepo::init_or_open(bailiff_repo_path_for_init)?;
        write_decision_note(&repo, &note).map_err(DecideError::Write)
    })
    .await
    .map_err(|e| format!("decide task failed: {e}"))?;

    match result {
        Ok(_target_oid) => Ok(()),
        Err(DecideError::OpenRepo(e)) => Err(format!(
            "opening bailiff repo at {}: {e}",
            bailiff_repo_path.display()
        )
        .into()),
        Err(DecideError::Write(WriteDecisionNoteError::DecisionAlreadyRecorded {
            plan_id,
            target_oid,
        })) => Err(format!(
            "decision already recorded for plan {plan_id} at target {target_oid}; bailiff does not overwrite verdicts — submit a fresh plan if the operator wants to change course"
        )
        .into()),
        Err(DecideError::Write(e)) => Err(format!("recording decision: {e}").into()),
    }
}

/// Tagged failure modes for the `spawn_blocking` decide closure.
/// Lets the post-await arm distinguish "the repo path is bad" from
/// "the duplicate-decide invariant fired" so the caller-facing stderr
/// is specific. Local to this binary; not part of any wire contract.
enum DecideError {
    OpenRepo(writ::notes_repo::NotesRepoError),
    Write(WriteDecisionNoteError),
}

impl From<writ::notes_repo::NotesRepoError> for DecideError {
    fn from(e: writ::notes_repo::NotesRepoError) -> Self {
        DecideError::OpenRepo(e)
    }
}

/// Map the parsed `--accept` / `--reject` flags to a [`Decision`].
/// Clap's `ArgGroup` enforces exactly-one before we get here, so the
/// `(false, false)` and `(true, true)` cases are unreachable in
/// practice — they panic loudly rather than guess.
fn resolve_decision_outcome(accept: bool, reject: bool) -> Decision {
    match (accept, reject) {
        (true, false) => Decision::Accepted,
        (false, true) => Decision::Rejected,
        (false, false) | (true, true) => {
            unreachable!("clap ArgGroup enforces exactly one of --accept / --reject")
        }
    }
}

/// Resolve the [`Decider`] from the `--decider` flag or fall back to
/// `cli:<user>` where `user` is the caller-supplied `$USER` value.
/// Fails with a user-actionable message if neither source produces a
/// non-empty value.
///
/// `user_env` is injected (not read from the live process) so tests
/// don't have to mutate the global env — concurrent test execution
/// in this binary used to race on `$USER`. Callers in `main()` pass
/// `std::env::var("USER").ok().filter(|s| !s.is_empty())`.
///
/// Diverges from writ's legacy `plan decide`, which falls back to
/// `cli:unknown` — see `PlanCmd::Decide`'s docstring for the
/// reasoning. The fallback gap is small (writ's verb is going away in
/// slice G) and the strictness is the bailiff-side default we want to
/// keep.
fn resolve_decider(
    flag: Option<String>,
    user_env: Option<String>,
) -> Result<Decider, Box<dyn std::error::Error>> {
    let raw = match flag {
        Some(explicit) => explicit,
        None => match user_env {
            Some(u) => format!("cli:{u}"),
            None => {
                return Err("no --decider flag and $USER is unset; pass --decider <attribution> or set $USER before running `bailiff plan decide`".into());
            }
        },
    };
    Decider::try_new(raw.clone()).map_err(|e| format!("--decider {raw:?} rejected: {e}").into())
}

fn xdg_data_subdir(suffix: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join(suffix)
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share").join(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// `bailiff plan submit` parses the minimal required flag set
    /// and threads each argument into the corresponding field of
    /// `PlanCmd::Submit`. A regression in the clap attribute set
    /// (a renamed flag, a misspelled default, a long/short
    /// collision) surfaces here as a parse failure or a wrong
    /// field assignment.
    #[test]
    fn plan_submit_parses_minimum_required_flags() {
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "submit",
            "--prompt-file",
            "/tmp/p.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Submit {
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    plan_id,
                    purpose,
                    label,
                    agent,
                    model,
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Submit");
        };
        assert_eq!(prompt_file, PathBuf::from("/tmp/p.txt"));
        assert_eq!(repo, "smaug123/writ");
        assert!(bailiff_repo.is_none());
        assert!(writ_repo.is_none());
        assert_eq!(
            writ_allowed_signers,
            PathBuf::from("/etc/bailiff/allowed_signers")
        );
        assert!(plan_id.is_none());
        assert_eq!(purpose, "plan-submit");
        assert!(label.is_none());
        assert_eq!(agent, AgentKind::Claude);
        assert!(model.is_none());
    }

    /// Every optional flag round-trips. Pins the contract that the
    /// CLI surface is what later scripting depends on.
    #[test]
    fn plan_submit_accepts_every_optional_flag() {
        let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "submit",
            "--prompt-file",
            "/tmp/p.txt",
            "--repo",
            "smaug123/writ",
            "--bailiff-repo",
            "/var/bailiff",
            "--writ-repo",
            "/var/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
            "--plan-id",
            plan_id_str,
            "--purpose",
            "plan-submit:rev-2",
            "--label",
            "feature 42",
            "--agent",
            "codex",
            "--model",
            "gpt-test",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Submit {
                    bailiff_repo,
                    writ_repo,
                    plan_id,
                    purpose,
                    label,
                    agent,
                    model,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Submit");
        };
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff"))
        );
        assert_eq!(
            writ_repo.as_deref(),
            Some(std::path::Path::new("/var/writ"))
        );
        assert_eq!(plan_id.unwrap().to_string(), plan_id_str);
        assert_eq!(purpose, "plan-submit:rev-2");
        assert_eq!(label.as_deref(), Some("feature 42"));
        assert_eq!(agent, AgentKind::Codex);
        assert_eq!(model.as_deref(), Some("gpt-test"));
    }

    /// `bailiff plan decide` parses the minimum required flag set
    /// (`--plan-id` plus exactly one of `--accept` / `--reject`) and
    /// threads each argument into the corresponding field of
    /// `PlanCmd::Decide`. A regression in the clap attribute set
    /// (a renamed flag, a missing `ArgGroup`, a misspelled default)
    /// surfaces here as a parse failure or a wrong field assignment.
    #[test]
    fn plan_decide_parses_minimum_required_flags() {
        let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "decide",
            "--plan-id",
            plan_id_str,
            "--accept",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Decide {
                    plan_id,
                    accept,
                    reject,
                    decider,
                    bailiff_repo,
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Decide");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert!(accept);
        assert!(!reject);
        assert!(
            decider.is_none(),
            "default decider derivation belongs to plan_decide, not the parser"
        );
        assert!(bailiff_repo.is_none());
    }

    /// Every optional flag round-trips, and `--reject` flips the
    /// outcome from accept to reject. Together with the
    /// minimum-required test this pins both halves of the
    /// accept/reject group plus the optional flag surface.
    #[test]
    fn plan_decide_accepts_every_optional_flag_with_reject() {
        let plan_id_str = "2d2d2d2d-3d3d-4d4d-5d5d-6d6d6d6d6d6d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "decide",
            "--plan-id",
            plan_id_str,
            "--reject",
            "--decider",
            "cli:alice",
            "--bailiff-repo",
            "/var/bailiff",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Decide {
                    plan_id,
                    accept,
                    reject,
                    decider,
                    bailiff_repo,
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Decide");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert!(!accept);
        assert!(reject);
        assert_eq!(decider.as_deref(), Some("cli:alice"));
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff")),
        );
    }

    /// Clap's `ArgGroup` on the outcome flags must reject both
    /// `--accept` and `--reject`. A regression that drops the group
    /// (or that uses `multiple = true`) would silently accept this
    /// and make `resolve_decision_outcome`'s `(true, true)` branch
    /// reachable from the CLI.
    #[test]
    fn plan_decide_rejects_both_accept_and_reject() {
        let plan_id_str = "3d3d3d3d-4d4d-5d5d-6d6d-7d7d7d7d7d7d";
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "decide",
            "--plan-id",
            plan_id_str,
            "--accept",
            "--reject",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--accept") || msg.contains("--reject") || msg.contains("decide_outcome"),
            "expected ArgGroup conflict, got: {msg}",
        );
    }

    /// `ArgGroup::required(true)` must reject the no-outcome case.
    /// A regression that drops `required(true)` would silently pass
    /// `(accept=false, reject=false)` through and trip
    /// `resolve_decision_outcome`'s `unreachable!`.
    #[test]
    fn plan_decide_rejects_neither_accept_nor_reject() {
        let plan_id_str = "4d4d4d4d-5d5d-6d6d-7d7d-8d8d8d8d8d8d";
        let err = Args::try_parse_from(["bailiff", "plan", "decide", "--plan-id", plan_id_str])
            .err()
            .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--accept") || msg.contains("--reject") || msg.contains("required"),
            "expected required-arg-group failure, got: {msg}",
        );
    }

    /// `--plan-id` is required; without it the parse fails. Pins the
    /// clap surface — a regression to `Option<PlanId>` (a copy-paste
    /// of `plan submit`'s opt-in shape) would silently accept this.
    #[test]
    fn plan_decide_rejects_missing_plan_id() {
        let err = Args::try_parse_from(["bailiff", "plan", "decide", "--accept"])
            .err()
            .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("required"),
            "expected missing-plan-id failure, got: {msg}",
        );
    }

    /// `PlanId::from_str` runs at parse, so a malformed UUID is a
    /// parse error rather than a runtime failure inside
    /// `plan_decide`. Pins that the value_parser stays wired to the
    /// validating constructor.
    #[test]
    fn plan_decide_rejects_malformed_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "decide",
            "--plan-id",
            "not-a-uuid",
            "--accept",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
            "expected malformed-plan-id failure, got: {msg}",
        );
    }

    /// `resolve_decision_outcome` is the load-bearing
    /// flag-to-`Decision` mapping. Pin both reachable branches —
    /// a swap (`accept` → `Rejected`) would be catastrophically wrong
    /// but invisible to the parser-only tests above.
    #[test]
    fn resolve_decision_outcome_maps_accept_and_reject() {
        assert_eq!(resolve_decision_outcome(true, false), Decision::Accepted);
        assert_eq!(resolve_decision_outcome(false, true), Decision::Rejected);
    }

    /// `resolve_decider` honours an explicit `--decider` flag
    /// verbatim, ignoring the supplied `user_env`. The flag is the
    /// override path scripted callers use; it must not be silently
    /// overridden by the env-var fallback even when one is present.
    #[test]
    fn resolve_decider_honours_explicit_flag() {
        let d = resolve_decider(Some("agent:run-xyz".into()), Some("alice".into())).unwrap();
        assert_eq!(d.as_str(), "agent:run-xyz");
    }

    /// Without `--decider`, `resolve_decider` falls back to
    /// `cli:<user_env>`. The env value is injected (not read from the
    /// live process), so this is a pure function and doesn't race
    /// with other tests in the same binary.
    #[test]
    fn resolve_decider_defaults_to_cli_user() {
        let d = resolve_decider(None, Some("alice".into())).unwrap();
        assert_eq!(d.as_str(), "cli:alice");
    }

    /// Without `--decider` and with `user_env = None`,
    /// `resolve_decider` fails with a user-actionable message
    /// mentioning both fallback sources. Diverges from writ's legacy
    /// `plan decide` (which falls back to `cli:unknown`); the
    /// `PlanCmd::Decide` docstring explains why. Pin the failure
    /// shape so the divergence is intentional rather than a silent
    /// regression.
    #[test]
    fn resolve_decider_fails_when_no_flag_and_no_user_env() {
        let err = resolve_decider(None, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--decider") && msg.contains("USER"),
            "expected actionable error mentioning both --decider and USER, got: {msg}",
        );
    }

    /// `default_bailiff_repo_path` honours `XDG_DATA_HOME` when
    /// set and falls back to the documented `~/.local/share`
    /// location otherwise. The env-var manipulation is process-
    /// scoped; running other tests concurrently in the same
    /// process could see the temporary unset, so the test serialises
    /// the env access by snapshotting and restoring.
    #[test]
    fn default_paths_track_xdg_data_home() {
        // Snapshot to restore; SAFETY-WISE we never share env access with
        // other parallel tests in this binary that mutate the same vars.
        // The `tests` module in this binary doesn't touch XDG_DATA_HOME
        // anywhere else, so the only risk is concurrent integration
        // tests — none exist for this binary today.
        let snapshot = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_DATA_HOME", "/data");
        }
        assert_eq!(
            default_bailiff_repo_path(),
            PathBuf::from("/data/bailiff/repo")
        );
        assert_eq!(default_writ_repo_path(), PathBuf::from("/data/writ/repo"));
        // Pin the invariant: bailiff's writ-repo default must agree
        // with the daemon's notes-repo default, because writd writes
        // and bailiff fetches from the same disk location when both
        // run with stock config.
        assert_eq!(
            default_writ_repo_path(),
            writ::config::default_notes_repo_path(),
            "bailiff and writd default writ-repo path diverged — one was renamed without the other",
        );

        unsafe {
            std::env::remove_var("XDG_DATA_HOME");
            std::env::set_var("HOME", "/home/test");
        }
        assert_eq!(
            default_bailiff_repo_path(),
            PathBuf::from("/home/test/.local/share/bailiff/repo")
        );
        assert_eq!(
            default_writ_repo_path(),
            PathBuf::from("/home/test/.local/share/writ/repo")
        );

        unsafe {
            match snapshot {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }
}
