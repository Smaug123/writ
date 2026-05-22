//! `bailiff` — the workflow orchestrator that drives plan submission
//! (and, in later slices, execute) on top of writ's `RunAgent` RPC.
//! See `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! Slice C3 introduces the first operator-facing verb,
//! `bailiff plan submit`: open a writ session, run the planner agent,
//! verify writ's signed envelope, and persist a
//! [`writ::bailiff_plan_note::PlanNote`] in bailiff's own bare repo.
//! The workflow itself lives in
//! [`writ::bailiff_plan_submit::submit_plan`]; this binary is the
//! thin CLI layer that resolves paths, parses flags, and prints the
//! plan id on success. Slice D2.5 adds the parallel `bailiff plan
//! review` verb, which reads the submission note, runs the reviewer
//! agent through writ, and persists a
//! [`writ::bailiff_plan_note::ReviewNote`]. The implement verb
//! mirrors review but grants the implementer agent
//! `WorkspaceWrite`, composes the operator's feature prompt with the
//! verified plan body, and persists a
//! [`writ::bailiff_plan_note::ImplementNote`].
//!
//! Paths default to the same XDG convention `docs/design/broker.md`
//! pins for writ, mirrored under `bailiff/`:
//! `$XDG_DATA_HOME/bailiff/repo` for bailiff's bare repo and
//! `$XDG_DATA_HOME/writ/repo` for the writ-owned repo bailiff
//! fetches from. `--bailiff-repo` and `--writ-repo` override either.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{ArgGroup, Parser, Subcommand};
use tokio::sync::Mutex as AsyncMutex;

use writ::agent_run::AgentPrompt;
use writ::bailiff_decision::{Decider, Decision};
use writ::bailiff_plan_implement::{SubmitImplementError, SubmitImplementInputs, submit_implement};
use writ::bailiff_plan_note::{DecisionNote, PlanId};
use writ::bailiff_plan_read::{list_plan_ids, read_full_plan, summarize_plan};
use writ::bailiff_plan_review::{SubmitReviewError, SubmitReviewInputs, submit_review};
use writ::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
use writ::bailiff_plan_write::{
    WriteDecisionNoteError, WriteImplementNoteError, WriteReviewNoteError, write_decision_note,
};
use writ::cli::output::{write_bailiff_plan_list, write_bailiff_plan_show};
use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::server::default_socket_path;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, WorkspaceWarmMode};
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
    /// Plan workflows: submit / decide / review / implement, plus
    /// the read-only list / show verbs.
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
    /// Run a reviewer agent against a previously-submitted plan and
    /// persist the bailiff-side review note. The plan body is fetched
    /// from writ's signed envelope, re-verified, and composed into
    /// the reviewer's prompt before the agent runs. Prints the review
    /// note's bailiff-side OID on success.
    ///
    /// Mirrors [`PlanCmd::Submit`] minus auto-allocation of
    /// `--plan-id` (review needs an existing plan) and with
    /// `--purpose` defaulting to `"plan-review"`.
    Review {
        /// Plan to review. Must parse as the canonical UUID form
        /// `PlanId` prints. Unlike `plan submit`, the id is required:
        /// there is no auto-allocation, since reviewing presupposes
        /// an existing submission.
        #[arg(long)]
        plan_id: PlanId,
        /// File containing the reviewer instructions. The bytes are
        /// read once, validated through [`AgentPrompt::try_new`], and
        /// passed to [`submit_review`] which composes them with the
        /// fetched plan body before handing the result to writ.
        #[arg(long)]
        prompt_file: PathBuf,
        /// Repository the reviewer agent is allowed to read, in
        /// `owner/name` form. D2.5 grants a single `WorkspaceRead`
        /// capability on this repo (matches `plan submit`'s shape).
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
        /// `$XDG_DATA_HOME/writ/repo`. Bailiff fetches writ's notes
        /// namespace from this path twice during a review: once to
        /// read the planner's envelope for plan-body extraction, once
        /// after the reviewer run to verify the reviewer envelope.
        #[arg(long)]
        writ_repo: Option<PathBuf>,
        /// OpenSSH `allowed_signers` file enumerating which writ
        /// signing keys bailiff will accept envelopes from. Used for
        /// both the planner re-verify (defence in depth) and the
        /// reviewer envelope.
        #[arg(long)]
        writ_allowed_signers: PathBuf,
        /// Opaque tag recorded verbatim on writ's audit row and on
        /// the bailiff-side review note. Defaults to `"plan-review"`.
        #[arg(long, default_value = "plan-review")]
        purpose: String,
        /// Human-readable session label stored in writ's audit log.
        /// Informational only.
        #[arg(long)]
        label: Option<String>,
        /// Coarse agent identity passed to writ's `OpenSession`.
        /// Defaults to `claude`, matching `plan submit`. Required by
        /// writ when a GitHub-app registry is configured.
        #[arg(long, default_value = "claude", value_parser = parse_agent_kind)]
        agent: AgentKind,
        /// Optional model identifier stored on writ's session row.
        #[arg(long)]
        model: Option<String>,
    },
    /// Run an implementer agent against a previously-submitted,
    /// *accepted* plan and persist the bailiff-side implement note.
    /// Bailiff fetches the planner envelope, re-verifies its
    /// signature, decodes the plan body, and composes the
    /// implementer's effective prompt as
    /// `--prompt-file bytes + separator + plan body` before handing
    /// the result to writ. The implementer is granted
    /// `WorkspaceWrite` on `--repo` so it can push; the pre-RPC
    /// duplicate gate refuses a second `bailiff plan implement` on
    /// the same plan to foreclose a double-push. Prints the implement
    /// note's bailiff-side OID on success.
    ///
    /// Pre-RPC gates the verb surfaces (each as a typed
    /// [`SubmitImplementError`] variant):
    /// - missing submission note → "run `bailiff plan submit` first"
    /// - missing decision note → "run `bailiff plan decide --accept` first"
    /// - rejected decision → "submit a fresh plan"
    /// - already-implemented → "submit a fresh plan if a re-implement
    ///   is needed"
    ///
    /// Mirrors [`PlanCmd::Review`] minus auto-allocation of
    /// `--plan-id` (implement needs an existing, decided plan), with
    /// `--purpose` defaulting to `"plan-implement"`, and with the
    /// implementer's capability set being `WorkspaceWrite` rather
    /// than `WorkspaceRead`.
    Implement {
        /// Plan to implement. Must parse as the canonical UUID form
        /// `PlanId` prints. As with `review`, the id is required:
        /// there is no auto-allocation, since implementing
        /// presupposes an existing accepted plan.
        #[arg(long)]
        plan_id: PlanId,
        /// File containing the operator's original feature prompt —
        /// the request that triggered the plan in the first place.
        /// The bytes are read once, validated through
        /// [`AgentPrompt::try_new`], and passed to [`submit_implement`]
        /// which composes them with the verified plan body before
        /// handing the result to writ. Crucially this is **not** the
        /// plan body; `submit_implement` decodes that from the signed
        /// planner envelope itself.
        #[arg(long)]
        prompt_file: PathBuf,
        /// Repository the implementer agent is allowed to write to,
        /// in `owner/name` form. Granted as a `WorkspaceWrite`
        /// capability (the difference from `plan submit` / `plan
        /// review`, which grant `WorkspaceRead`); the
        /// `WorkspaceWrite` is what lets the agent push, and is the
        /// reason the duplicate gate inside `submit_implement` is
        /// load-bearing.
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
        /// `$XDG_DATA_HOME/writ/repo`. Bailiff fetches writ's notes
        /// namespace from this path twice during an implement run:
        /// once to read the planner's envelope for plan-body
        /// extraction, once after the implementer run to verify the
        /// implementer envelope.
        #[arg(long)]
        writ_repo: Option<PathBuf>,
        /// OpenSSH `allowed_signers` file enumerating which writ
        /// signing keys bailiff will accept envelopes from. Used for
        /// both the planner re-verify (defence in depth) and the
        /// implementer envelope.
        #[arg(long)]
        writ_allowed_signers: PathBuf,
        /// Opaque tag recorded verbatim on writ's audit row and on
        /// the bailiff-side implement note. Defaults to
        /// `"plan-implement"`.
        #[arg(long, default_value = "plan-implement")]
        purpose: String,
        /// Human-readable session label stored in writ's audit log.
        /// Informational only.
        #[arg(long)]
        label: Option<String>,
        /// Coarse agent identity passed to writ's `OpenSession`. With
        /// `WorkspaceWrite` granted, this field selects which GitHub
        /// App writ uses to mint push credentials. Defaults to
        /// `claude`.
        #[arg(long, default_value = "claude", value_parser = parse_agent_kind)]
        agent: AgentKind,
        /// Optional model identifier stored on writ's session row.
        #[arg(long)]
        model: Option<String>,
        /// How aggressively to pre-warm the per-run VM checkout
        /// before the agent runs. `none` does nothing,
        /// `sources` fetches Nix sources for the flake's
        /// `devShell`, and `devshell` (the default) materialises
        /// the dev-shell environment in full. The cost / hit-rate
        /// trade-off is operator-tunable per invocation;
        /// `devshell` matches what the broker would do on its own
        /// if the operator omitted the flag.
        #[arg(long, default_value = "devshell", value_parser = parse_workspace_warm)]
        workspace_warm: WorkspaceWarmMode,
        /// Override the workspace checkout location inside the VM.
        /// Defaults to `default_workspace_destination(repo)`
        /// (`/workspace/<repo-name>`); only override if a flake
        /// expects the checkout at a different path.
        #[arg(long)]
        workspace_destination: Option<PathBuf>,
    },
    /// Enumerate every plan in bailiff's repo. Lists plan id +
    /// workflow state + the four per-stage timestamps, one
    /// key=value block per plan separated by blank lines. Empty
    /// repo prints a single `no plans` line, exit 0.
    ///
    /// Slice F's read-only verb. Verifies nothing — each row is
    /// metadata pulled from bailiff's own notes; `bailiff plan show`
    /// (slice F4) is where writ-side signature verification happens.
    List {
        /// Path to bailiff's bare git repo. Defaults to
        /// `$XDG_DATA_HOME/bailiff/repo` (or
        /// `~/.local/share/bailiff/repo` if `XDG_DATA_HOME` is
        /// unset). Created on first use via
        /// [`NotesRepo::init_or_open`] — listing an empty repo is
        /// not an error.
        #[arg(long)]
        bailiff_repo: Option<PathBuf>,
    },
    /// Render every available note for one plan, verifying the
    /// writ-side envelope per signed section. Reads bailiff's own
    /// notes plus bailiff's local copy of writ's
    /// `refs/notes/writ/v1/agent-outputs`; does NOT touch the writ
    /// socket and does NOT fetch from writ. If the operator wants
    /// "show what's on writ right now," they should re-run the
    /// relevant `submit*` verb to bring fresh envelopes across.
    ///
    /// Slice F's per-plan read verb. Sections render in a fixed
    /// order — Plan / Decision / Review / Implement — each headed by
    /// its verification status; missing-because-not-yet-written
    /// sections render with an explicit `<none>` and a
    /// missing-because-not-fetched section renders with the failure
    /// noted explicitly (see `VerifiedSection`).
    Show {
        /// Plan to render. Must parse as the canonical UUID form
        /// `PlanId` prints. Matches `decide` and `review`'s flag
        /// shape rather than taking the id as a positional, so the
        /// three per-plan verbs feel consistent.
        #[arg(long)]
        plan_id: PlanId,
        /// OpenSSH `allowed_signers` file enumerating which writ
        /// signing keys bailiff will accept envelopes from. Used by
        /// every signed section's verification step.
        #[arg(long)]
        writ_allowed_signers: PathBuf,
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

/// clap value parser for `--workspace-warm`. Matches the JSON
/// `snake_case` rendering of [`WorkspaceWarmMode`] so the on-disk and
/// CLI surfaces stay aligned: a config dumper that round-trips a
/// bootstrap through JSON and a CLI operator typing the flag both
/// spell the variants the same way.
fn parse_workspace_warm(raw: &str) -> Result<WorkspaceWarmMode, String> {
    match raw {
        "none" => Ok(WorkspaceWarmMode::None),
        "sources" => Ok(WorkspaceWarmMode::Sources),
        "devshell" => Ok(WorkspaceWarmMode::DevShell),
        other => Err(format!(
            "expected `none`, `sources`, or `devshell`, got {other:?}"
        )),
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
            PlanCmd::Review {
                plan_id,
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                purpose,
                label,
                agent,
                model,
            } => {
                plan_review(
                    socket_path,
                    plan_id,
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    purpose,
                    label,
                    agent,
                    model,
                )
                .await
            }
            PlanCmd::Implement {
                plan_id,
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                purpose,
                label,
                agent,
                model,
                workspace_warm,
                workspace_destination,
            } => {
                plan_implement(
                    socket_path,
                    plan_id,
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    purpose,
                    label,
                    agent,
                    model,
                    workspace_warm,
                    workspace_destination,
                )
                .await
            }
            PlanCmd::List { bailiff_repo } => plan_list(bailiff_repo).await,
            PlanCmd::Show {
                plan_id,
                writ_allowed_signers,
                bailiff_repo,
            } => plan_show(plan_id, writ_allowed_signers, bailiff_repo).await,
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

#[allow(clippy::too_many_arguments)]
async fn plan_review(
    socket_path: PathBuf,
    plan_id: PlanId,
    prompt_file: PathBuf,
    repo: String,
    bailiff_repo: Option<PathBuf>,
    writ_repo: Option<PathBuf>,
    writ_allowed_signers: PathBuf,
    purpose: String,
    label: Option<String>,
    agent: AgentKind,
    model: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same pre-RPC discipline as `plan_submit`: validate every
    // on-disk input before opening any sockets, so a typo in
    // `--prompt-file` or `--writ-allowed-signers` fails before
    // bailiff makes a side-effecting writ call.
    let prompt_bytes = std::fs::read(&prompt_file)
        .map_err(|e| format!("reading prompt file {}: {e}", prompt_file.display()))?;
    let prompt_str = String::from_utf8(prompt_bytes).map_err(|e| {
        format!(
            "prompt file {} is not valid UTF-8: {e}",
            prompt_file.display()
        )
    })?;
    let reviewer_instructions = AgentPrompt::try_new(prompt_str)
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

    let writ_output_ref =
        NotesRef::try_new(WRIT_OUTPUT_REF).expect("WRIT_OUTPUT_REF is a static well-formed ref");

    let inputs = SubmitReviewInputs {
        plan_id,
        reviewer_instructions,
        capabilities: vec![CapabilitySet::WorkspaceRead { repo }],
        purpose,
        writ_output_ref,
        session_label: label,
        session_agent_kind: Some(agent),
        session_agent_model: model,
    };

    let client = WritClient::new(&socket_path);
    match submit_review(&client, bailiff, &writ_repo_path, allowed, inputs).await {
        Ok(outcome) => {
            println!("{}", outcome.review_note_oid);
            Ok(())
        }
        // `ReviewAlreadyRecorded` is the duplicate-review invariant.
        // Surface it with the same actionable shape `plan decide`
        // uses for `DecisionAlreadyRecorded`, so an operator who
        // re-ran the verb sees what to do next rather than a generic
        // formatted error chain.
        Err(SubmitReviewError::WriteReviewNote {
            session_id: _,
            source:
                WriteReviewNoteError::ReviewAlreadyRecorded {
                    plan_id,
                    target_oid,
                },
        }) => Err(format!(
            "review already recorded for plan {plan_id} at target {target_oid}; bailiff does not \
             overwrite reviews — submit a fresh plan if the operator wants a re-review (multi-review \
             history is a future v1 → v2 migration)"
        )
        .into()),
        Err(e) => Err(format!("{e}").into()),
    }
}

/// Repo-scoped exclusive lockfile guard for cross-process serialisation
/// of `bailiff plan implement` runs.
///
/// The library workflow ([`submit_implement`]) takes an
/// `Arc<AsyncMutex<NotesRepo>>` for the in-process single-writer
/// invariant via [`writ::bailiff_repo_guard::BailiffRepoGuard`], but
/// the CLI constructs a fresh `Arc` per invocation, so two CLI
/// processes against the same `--bailiff-repo` can each pass the
/// in-process pre-RPC `AlreadyImplemented` gate, both kick off
/// `WorkspaceWrite`-capable agent runs (with `git push` side effects
/// minted by writ), and only the second's notes-add loses the
/// duplicate-implement race. The `BailiffRepoGuard` module docstring
/// names git's notes-add idempotency at the seed OID as the
/// cross-process fallback — that fallback fires *after* the agent has
/// already executed, which is acceptable for `WorkspaceRead` verbs
/// (no externally-observable side effects) but is load-bearing for
/// `WorkspaceWrite`.
///
/// The lockfile lives at `<bailiff_repo>/bailiff-implement.lock` and
/// is held by an OS-level advisory `flock` (`std::fs::File::try_lock`).
/// Distinct `--bailiff-repo` paths do not contend. The lock is
/// released when the returned `File` is dropped, or — as a backstop
/// against unclean exits — when the process terminates and the kernel
/// closes the descriptor.
fn acquire_implement_lock(bailiff_repo_path: &Path) -> Result<File, String> {
    let lock_path = bailiff_repo_path.join("bailiff-implement.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("opening implement lockfile {}: {e}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!(
            "another `bailiff plan implement` is in progress against {}; retry once it finishes \
             (lockfile at {})",
            bailiff_repo_path.display(),
            lock_path.display(),
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(format!(
            "acquiring implement lockfile at {}: {e}",
            lock_path.display()
        )),
    }
}

/// Drive `submit_implement` from the CLI: read the feature prompt and
/// allowed-signers file, open bailiff's repo, build the inputs (with
/// the single `WorkspaceWrite` capability that distinguishes this
/// verb from `submit` / `review`), call the workflow, and surface its
/// outcome.
///
/// The error-mapping arms below cover the variants where the
/// passthrough `format!("{e}")` would be the wrong shape — either
/// because the operator's recourse is non-obvious from
/// [`SubmitImplementError`]'s `#[error]` message alone, or because the
/// invariant lives in a wrapped error and the unwrapped message would
/// not name it. The remaining variants fall through to the passthrough
/// because their existing `#[error]` strings already name the broken
/// precondition.
#[allow(clippy::too_many_arguments)]
async fn plan_implement(
    socket_path: PathBuf,
    plan_id: PlanId,
    prompt_file: PathBuf,
    repo: String,
    bailiff_repo: Option<PathBuf>,
    writ_repo: Option<PathBuf>,
    writ_allowed_signers: PathBuf,
    purpose: String,
    label: Option<String>,
    agent: AgentKind,
    model: Option<String>,
    workspace_warm: WorkspaceWarmMode,
    workspace_destination: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same pre-RPC discipline as `plan_submit` / `plan_review`:
    // validate every on-disk input before opening any sockets, so a
    // typo in `--prompt-file` or `--writ-allowed-signers` fails before
    // bailiff makes a side-effecting writ call.
    let prompt_bytes = std::fs::read(&prompt_file)
        .map_err(|e| format!("reading prompt file {}: {e}", prompt_file.display()))?;
    let prompt_str = String::from_utf8(prompt_bytes).map_err(|e| {
        format!(
            "prompt file {} is not valid UTF-8: {e}",
            prompt_file.display()
        )
    })?;
    let feature_prompt = AgentPrompt::try_new(prompt_str)
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

    // Cross-process flock: distinct from the in-process `Arc<AsyncMutex>`
    // above, which only serialises callers sharing this CLI process.
    // Two concurrent `bailiff plan implement` processes would both pass
    // `submit_implement`'s pre-RPC `AlreadyImplemented` gate and both
    // launch `WorkspaceWrite` agent runs before either reached the final
    // notes-add. Held to scope end (Drop releases) so the lock spans the
    // entire workflow.
    let _implement_lock = acquire_implement_lock(&bailiff_repo_path)?;

    let writ_output_ref =
        NotesRef::try_new(WRIT_OUTPUT_REF).expect("WRIT_OUTPUT_REF is a static well-formed ref");

    // Workspace bootstrap routes the run into writd's VM dispatch
    // arm. The bootstrap repo and the `WorkspaceWrite` capability
    // must agree on `owner/name` — both come from `--repo` so they
    // do by construction.
    let workspace_repo = GitCloneRepo::new(repo.clone())
        .map_err(|e| format!("--repo {repo} is not a valid workspace target: {e}"))?;
    let workspace = AgentVmWorkspaceBootstrap {
        repo: workspace_repo,
        destination: workspace_destination,
        warm: workspace_warm,
    };

    let inputs = SubmitImplementInputs {
        plan_id,
        feature_prompt,
        capabilities: vec![CapabilitySet::WorkspaceWrite { repo }],
        purpose,
        writ_output_ref,
        session_label: label,
        session_agent_kind: Some(agent),
        session_agent_model: model,
        workspace,
    };

    let client = WritClient::new(&socket_path);
    match submit_implement(&client, bailiff, &writ_repo_path, allowed, inputs).await {
        Ok(outcome) => {
            println!("{}", outcome.implement_note_oid);
            Ok(())
        }
        // The four pre-RPC gates each get a message that names the
        // operator's next step. Same shape `plan_review` uses for
        // `ReviewAlreadyRecorded`.
        Err(SubmitImplementError::PlanSubmissionMissing { plan_id }) => Err(format!(
            "no plan submission note recorded for plan {plan_id}; run `bailiff plan submit` first"
        )
        .into()),
        Err(SubmitImplementError::PlanNotDecided { plan_id }) => Err(format!(
            "no decision recorded for plan {plan_id}; run `bailiff plan decide --accept` first"
        )
        .into()),
        Err(SubmitImplementError::PlanRejected { plan_id }) => Err(format!(
            "plan {plan_id} was rejected; refusing to implement a rejected plan — submit a fresh \
             plan if the operator wants to try a different approach"
        )
        .into()),
        Err(SubmitImplementError::AlreadyImplemented { plan_id }) => Err(format!(
            "implement already recorded for plan {plan_id}; bailiff does not re-run the \
             implementer — submit a fresh plan if a re-implement is needed (multi-attempt \
             implement history is a future v1 → v2 migration)"
        )
        .into()),
        // Post-RPC variant of the same idempotency invariant: the
        // implementer agent ran and writ stamped an envelope, but
        // bailiff's note-write lost a race against another caller.
        // Recourse is identical to the pre-RPC `AlreadyImplemented`
        // case — same message, surfaced verbatim.
        Err(SubmitImplementError::WriteImplementNote {
            session_id: _,
            source:
                WriteImplementNoteError::ImplementAlreadyRecorded {
                    plan_id,
                    target_oid,
                },
        }) => Err(format!(
            "implement already recorded for plan {plan_id} at target {target_oid}; bailiff does \
             not overwrite implement notes — submit a fresh plan if a re-implement is needed \
             (multi-attempt implement history is a future v1 → v2 migration)"
        )
        .into()),
        Err(e) => Err(format!("{e}").into()),
    }
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

async fn plan_list(bailiff_repo: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let bailiff_repo_path = bailiff_repo.unwrap_or_else(default_bailiff_repo_path);

    // Both `init_or_open` and the read helpers shell out to git; do
    // them on a blocking thread so the runtime stays responsive
    // (mirrors the pattern `plan_submit` / `plan_decide` use). The
    // pure-data result (`Vec<BailiffPlanSummary>`) is what we hand to
    // the formatter on the runtime thread.
    let bailiff_repo_path_for_task = bailiff_repo_path.clone();
    let result: Result<Vec<_>, ListError> = tokio::task::spawn_blocking(move || {
        let repo = NotesRepo::init_or_open(bailiff_repo_path_for_task)?;
        let ids = list_plan_ids(&repo).map_err(ListError::List)?;
        let mut summaries = Vec::with_capacity(ids.len());
        for id in ids {
            summaries.push(summarize_plan(&repo, id).map_err(ListError::Summarize)?);
        }
        Ok(summaries)
    })
    .await
    .map_err(|e| format!("list task failed: {e}"))?;

    let summaries = match result {
        Ok(s) => s,
        Err(ListError::OpenRepo(e)) => {
            return Err(format!(
                "opening bailiff repo at {}: {e}",
                bailiff_repo_path.display()
            )
            .into());
        }
        Err(ListError::List(e)) => return Err(format!("listing plans: {e}").into()),
        Err(ListError::Summarize(e)) => return Err(format!("summarizing plan: {e}").into()),
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_bailiff_plan_list(&mut handle, &summaries)?;
    Ok(())
}

/// Tagged failure modes for the `spawn_blocking` list closure.
/// Mirrors `DecideError`'s pattern: tag enough to give the post-await
/// arm a specific error message rather than collapsing everything
/// into a single string. Local to this binary; not a wire contract.
enum ListError {
    OpenRepo(writ::notes_repo::NotesRepoError),
    List(writ::bailiff_plan_read::ListPlanIdsError),
    Summarize(writ::bailiff_plan_read::SummarizePlanError),
}

impl From<writ::notes_repo::NotesRepoError> for ListError {
    fn from(e: writ::notes_repo::NotesRepoError) -> Self {
        ListError::OpenRepo(e)
    }
}

async fn plan_show(
    plan_id: PlanId,
    writ_allowed_signers: PathBuf,
    bailiff_repo: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Pre-RPC discipline: read & parse the allowed-signers file
    // before any git work, so a bad path or malformed file surfaces
    // before bailiff opens its repo.
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

    let bailiff_repo_path = bailiff_repo.unwrap_or_else(default_bailiff_repo_path);

    // Both `init_or_open` and `read_full_plan` shell out to git; do
    // them on a blocking thread so the runtime stays responsive
    // (mirrors `plan_list`). The pure-data result (`PlanFullView`) is
    // what we hand to the formatter on the runtime thread.
    let bailiff_repo_path_for_task = bailiff_repo_path.clone();
    let result: Result<_, ShowError> = tokio::task::spawn_blocking(move || {
        let repo = NotesRepo::init_or_open(bailiff_repo_path_for_task)?;
        read_full_plan(&repo, plan_id, &allowed).map_err(ShowError::ReadFullPlan)
    })
    .await
    .map_err(|e| format!("show task failed: {e}"))?;

    let view = match result {
        Ok(v) => v,
        Err(ShowError::OpenRepo(e)) => {
            return Err(format!(
                "opening bailiff repo at {}: {e}",
                bailiff_repo_path.display()
            )
            .into());
        }
        Err(ShowError::ReadFullPlan(e)) => return Err(format!("reading plan: {e}").into()),
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_bailiff_plan_show(&mut handle, &view)?;
    Ok(())
}

/// Tagged failure modes for the `spawn_blocking` show closure. Mirrors
/// `ListError` / `DecideError`'s pattern: tag enough to give the
/// post-await arm a specific error message rather than collapsing
/// everything into a single string. Local to this binary; not a wire
/// contract.
enum ShowError {
    OpenRepo(writ::notes_repo::NotesRepoError),
    ReadFullPlan(writ::bailiff_plan_read::ReadFullPlanError),
}

impl From<writ::notes_repo::NotesRepoError> for ShowError {
    fn from(e: writ::notes_repo::NotesRepoError) -> Self {
        ShowError::OpenRepo(e)
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

    /// `bailiff plan review` parses the minimum required flag set
    /// (`--plan-id`, `--prompt-file`, `--repo`, `--writ-allowed-signers`)
    /// and threads each argument into the corresponding field of
    /// `PlanCmd::Review`. A regression in the clap attribute set
    /// (a renamed flag, a misspelled default, a long/short collision)
    /// surfaces here as a parse failure or a wrong field assignment.
    #[test]
    fn plan_review_parses_minimum_required_flags() {
        let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "review",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/r.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Review {
                    plan_id,
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    purpose,
                    label,
                    agent,
                    model,
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Review");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert_eq!(prompt_file, PathBuf::from("/tmp/r.txt"));
        assert_eq!(repo, "smaug123/writ");
        assert!(bailiff_repo.is_none());
        assert!(writ_repo.is_none());
        assert_eq!(
            writ_allowed_signers,
            PathBuf::from("/etc/bailiff/allowed_signers")
        );
        assert_eq!(purpose, "plan-review");
        assert!(label.is_none());
        assert_eq!(agent, AgentKind::Claude);
        assert!(model.is_none());
    }

    /// Every optional flag round-trips. Pins the full review CLI
    /// surface so scripted callers see a stable contract.
    #[test]
    fn plan_review_accepts_every_optional_flag() {
        let plan_id_str = "2d2d2d2d-3d3d-4d4d-5d5d-6d6d6d6d6d6d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "review",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/r.txt",
            "--repo",
            "smaug123/writ",
            "--bailiff-repo",
            "/var/bailiff",
            "--writ-repo",
            "/var/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
            "--purpose",
            "plan-review:rev-2",
            "--label",
            "feature 42 review",
            "--agent",
            "codex",
            "--model",
            "gpt-test",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Review {
                    plan_id,
                    bailiff_repo,
                    writ_repo,
                    purpose,
                    label,
                    agent,
                    model,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Review");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff"))
        );
        assert_eq!(
            writ_repo.as_deref(),
            Some(std::path::Path::new("/var/writ"))
        );
        assert_eq!(purpose, "plan-review:rev-2");
        assert_eq!(label.as_deref(), Some("feature 42 review"));
        assert_eq!(agent, AgentKind::Codex);
        assert_eq!(model.as_deref(), Some("gpt-test"));
    }

    /// `--plan-id` is required; without it the parse fails. Pins the
    /// divergence from `plan submit` (which auto-allocates): reviewing
    /// presupposes an existing plan, so the id is mandatory.
    #[test]
    fn plan_review_rejects_missing_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "review",
            "--prompt-file",
            "/tmp/r.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("required"),
            "expected missing-plan-id failure, got: {msg}",
        );
    }

    /// `PlanId::from_str` runs at parse, so a malformed UUID is a
    /// parse error rather than a runtime failure inside `plan_review`.
    /// Pins that the value_parser stays wired to the validating
    /// constructor.
    #[test]
    fn plan_review_rejects_malformed_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "review",
            "--plan-id",
            "not-a-uuid",
            "--prompt-file",
            "/tmp/r.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
            "expected malformed-plan-id failure, got: {msg}",
        );
    }

    /// `bailiff plan list` parses with no required flags and accepts
    /// the single optional `--bailiff-repo` override. The body of
    /// `plan_list` (path resolution, repo init, ref enumeration,
    /// formatter) is exercised by the library-side helper tests in
    /// `bailiff_plan_read::list_tests` and `cli::output::tests` — the
    /// parser test pins the clap surface so a renamed flag surfaces
    /// here rather than as a confused operator running into an unknown
    /// argument message.
    #[test]
    fn plan_list_parses_with_no_flags() {
        let args = Args::try_parse_from(["bailiff", "plan", "list"]).unwrap();
        let Cmd::Plan {
            action: PlanCmd::List { bailiff_repo },
        } = args.cmd
        else {
            panic!("expected PlanCmd::List");
        };
        assert!(bailiff_repo.is_none());
    }

    /// `--bailiff-repo` round-trips. Pins the optional-flag contract;
    /// scripted callers that override the default path depend on this.
    #[test]
    fn plan_list_accepts_bailiff_repo_override() {
        let args =
            Args::try_parse_from(["bailiff", "plan", "list", "--bailiff-repo", "/var/bailiff"])
                .unwrap();
        let Cmd::Plan {
            action: PlanCmd::List { bailiff_repo },
        } = args.cmd
        else {
            panic!("expected PlanCmd::List");
        };
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff"))
        );
    }

    /// `bailiff plan show` parses the minimum required flag set
    /// (`--plan-id`, `--writ-allowed-signers`) and threads each
    /// argument into the corresponding field. Pins the clap surface
    /// so a renamed flag surfaces here rather than as a confused
    /// operator running into an unknown-argument message.
    #[test]
    fn plan_show_parses_minimum_required_flags() {
        let plan_id_str = "5d5d5d5d-6d6d-7d7d-8d8d-9d9d9d9d9d9d";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "show",
            "--plan-id",
            plan_id_str,
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Show {
                    plan_id,
                    writ_allowed_signers,
                    bailiff_repo,
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Show");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert_eq!(
            writ_allowed_signers,
            PathBuf::from("/etc/bailiff/allowed_signers")
        );
        assert!(bailiff_repo.is_none());
    }

    /// `--bailiff-repo` round-trips for `show`. Pins the optional-flag
    /// contract; scripted callers that override the default path
    /// depend on this.
    #[test]
    fn plan_show_accepts_bailiff_repo_override() {
        let plan_id_str = "6d6d6d6d-7d7d-8d8d-9d9d-1e1e1e1e1e1e";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "show",
            "--plan-id",
            plan_id_str,
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
            "--bailiff-repo",
            "/var/bailiff",
        ])
        .unwrap();
        let Cmd::Plan {
            action: PlanCmd::Show { bailiff_repo, .. },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Show");
        };
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff"))
        );
    }

    /// `--plan-id` is required. A regression that made it optional
    /// (a copy-paste of `plan submit`'s opt-in shape) would silently
    /// accept this and reach `plan_show` with a `None` id.
    #[test]
    fn plan_show_rejects_missing_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "show",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("required"),
            "expected missing-plan-id failure, got: {msg}",
        );
    }

    /// `--writ-allowed-signers` is required. A regression that made
    /// it optional would let `plan_show` reach the on-disk read with
    /// a `None` path; pin the contract here at the parser tier.
    #[test]
    fn plan_show_rejects_missing_writ_allowed_signers() {
        let plan_id_str = "7d7d7d7d-8d8d-9d9d-1e1e-2e2e2e2e2e2e";
        let err = Args::try_parse_from(["bailiff", "plan", "show", "--plan-id", plan_id_str])
            .err()
            .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--writ-allowed-signers") || msg.contains("required"),
            "expected missing-writ-allowed-signers failure, got: {msg}",
        );
    }

    /// `PlanId::from_str` runs at parse, so a malformed UUID is a
    /// parse error rather than a runtime failure inside `plan_show`.
    /// Pins that the value_parser stays wired to the validating
    /// constructor.
    #[test]
    fn plan_show_rejects_malformed_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "show",
            "--plan-id",
            "not-a-uuid",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
            "expected malformed-plan-id failure, got: {msg}",
        );
    }

    /// `--prompt-file` is required. A regression that made it optional
    /// would let `plan_review` reach the on-disk read with a `None`
    /// path; pin the contract here at the parser tier.
    #[test]
    fn plan_review_rejects_missing_prompt_file() {
        let plan_id_str = "3d3d3d3d-4d4d-5d5d-6d6d-7d7d7d7d7d7d";
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "review",
            "--plan-id",
            plan_id_str,
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--prompt-file") || msg.contains("required"),
            "expected missing-prompt-file failure, got: {msg}",
        );
    }

    /// `bailiff plan implement` parses the minimum required flag set
    /// (`--plan-id`, `--prompt-file`, `--repo`, `--writ-allowed-signers`)
    /// and threads each argument into the corresponding field of
    /// `PlanCmd::Implement`. The defaults pin the operator-facing
    /// contract: `--purpose` is `"plan-implement"` (parallels
    /// `plan-submit` / `plan-review`); `--agent` is `claude` to match
    /// the GitHub-App selection writ uses when no explicit identity is
    /// passed. A regression in the clap attribute set surfaces here
    /// rather than at runtime.
    #[test]
    fn plan_implement_parses_minimum_required_flags() {
        let plan_id_str = "1e1e1e1e-2e2e-3e3e-4e4e-5e5e5e5e5e5e";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Implement {
                    plan_id,
                    prompt_file,
                    repo,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    purpose,
                    label,
                    agent,
                    model,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Implement");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert_eq!(prompt_file, PathBuf::from("/tmp/i.txt"));
        assert_eq!(repo, "smaug123/writ");
        assert!(bailiff_repo.is_none());
        assert!(writ_repo.is_none());
        assert_eq!(
            writ_allowed_signers,
            PathBuf::from("/etc/bailiff/allowed_signers")
        );
        assert_eq!(purpose, "plan-implement");
        assert!(label.is_none());
        assert_eq!(agent, AgentKind::Claude);
        assert!(model.is_none());
    }

    /// Every optional flag round-trips. Pins the full implement CLI
    /// surface so scripted callers see a stable contract.
    #[test]
    fn plan_implement_accepts_every_optional_flag() {
        let plan_id_str = "2e2e2e2e-3e3e-4e4e-5e5e-6e6e6e6e6e6e";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--bailiff-repo",
            "/var/bailiff",
            "--writ-repo",
            "/var/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
            "--purpose",
            "plan-implement:rev-2",
            "--label",
            "feature 42 implement",
            "--agent",
            "codex",
            "--model",
            "gpt-test",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Implement {
                    plan_id,
                    bailiff_repo,
                    writ_repo,
                    purpose,
                    label,
                    agent,
                    model,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Implement");
        };
        assert_eq!(plan_id.to_string(), plan_id_str);
        assert_eq!(
            bailiff_repo.as_deref(),
            Some(std::path::Path::new("/var/bailiff"))
        );
        assert_eq!(
            writ_repo.as_deref(),
            Some(std::path::Path::new("/var/writ"))
        );
        assert_eq!(purpose, "plan-implement:rev-2");
        assert_eq!(label.as_deref(), Some("feature 42 implement"));
        assert_eq!(agent, AgentKind::Codex);
        assert_eq!(model.as_deref(), Some("gpt-test"));
    }

    /// `--plan-id` is required. Implementing presupposes a submitted +
    /// decided plan, so there is no auto-allocation — the id is
    /// mandatory. A regression to `Option<PlanId>` (a copy-paste of
    /// `plan submit`'s opt-in shape) would silently accept this and
    /// reach `plan_implement` with a `None` id.
    #[test]
    fn plan_implement_rejects_missing_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("required"),
            "expected missing-plan-id failure, got: {msg}",
        );
    }

    /// `--prompt-file` is required. Pins the surface — a regression
    /// that made it optional would let `plan_implement` reach the
    /// on-disk read with a `None` path. The clap-side doc on this flag
    /// must continue to read "the operator's original feature prompt"
    /// because `submit_implement` composes the implementer's effective
    /// prompt internally from this plus the verified plan body.
    #[test]
    fn plan_implement_rejects_missing_prompt_file() {
        let plan_id_str = "3e3e3e3e-4e4e-5e5e-6e6e-7e7e7e7e7e7e";
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            plan_id_str,
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--prompt-file") || msg.contains("required"),
            "expected missing-prompt-file failure, got: {msg}",
        );
    }

    /// `PlanId::from_str` runs at parse, so a malformed UUID is a
    /// parse error rather than a runtime failure inside `plan_implement`.
    /// Pins that the value_parser stays wired to the validating
    /// constructor.
    #[test]
    fn plan_implement_rejects_malformed_plan_id() {
        let err = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            "not-a-uuid",
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .err()
        .expect("expected parse error");
        let msg = err.to_string();
        assert!(
            msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
            "expected malformed-plan-id failure, got: {msg}",
        );
    }

    /// `bailiff plan implement` parses the workspace bootstrap flags
    /// (`--workspace-warm`, `--workspace-destination`) and threads them
    /// into `PlanCmd::Implement` so the CLI binding can build an
    /// `AgentVmWorkspaceBootstrap` for `SubmitImplementInputs`. Slice
    /// VM3 introduces the flags so `submit_implement` can request a
    /// per-run VM checkout; the workspace repo is taken from the
    /// existing `--repo` flag (`WorkspaceWrite` capability and the
    /// bootstrap target are the same `owner/name`). A regression that
    /// dropped either flag from the surface would surface here as a
    /// clap parse error or as a `None` on the parsed variant.
    #[test]
    fn plan_implement_parses_workspace_flags() {
        let plan_id_str = "4e4e4e4e-5e5e-6e6e-7e7e-8e8e8e8e8e8e";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
            "--workspace-warm",
            "sources",
            "--workspace-destination",
            "/repo",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Implement {
                    workspace_warm,
                    workspace_destination,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Implement");
        };
        assert_eq!(workspace_warm, WorkspaceWarmMode::Sources);
        assert_eq!(
            workspace_destination.as_deref(),
            Some(std::path::Path::new("/repo"))
        );
    }

    /// The workspace flags are optional with sensible defaults: omitted
    /// `--workspace-warm` defaults to `devshell` (the
    /// `WorkspaceWarmMode::Default` impl), and omitted
    /// `--workspace-destination` lands as `None` (so writd picks
    /// `default_workspace_destination` for the repo). A regression that
    /// made either flag required would force every operator invocation
    /// to spell out the default, which is contrary to the slice's
    /// "operator supplies repo, broker picks the rest" ergonomics.
    #[test]
    fn plan_implement_defaults_workspace_warm_to_devshell() {
        let plan_id_str = "5e5e5e5e-6e6e-7e7e-8e8e-9e9e9e9e9e9e";
        let args = Args::try_parse_from([
            "bailiff",
            "plan",
            "implement",
            "--plan-id",
            plan_id_str,
            "--prompt-file",
            "/tmp/i.txt",
            "--repo",
            "smaug123/writ",
            "--writ-allowed-signers",
            "/etc/bailiff/allowed_signers",
        ])
        .unwrap();
        let Cmd::Plan {
            action:
                PlanCmd::Implement {
                    workspace_warm,
                    workspace_destination,
                    ..
                },
        } = args.cmd
        else {
            panic!("expected PlanCmd::Implement");
        };
        assert_eq!(workspace_warm, WorkspaceWarmMode::DevShell);
        assert!(workspace_destination.is_none());
    }

    /// Acquire → second acquire fails fast → drop → reacquire round-trips.
    /// Pins the cross-process invariant the helper exists to enforce:
    /// two concurrent `bailiff plan implement` invocations against the
    /// same `--bailiff-repo` cannot both pass the lockfile. A regression
    /// (e.g. swapping `try_lock` for `lock`, dropping the lockfile path
    /// to a process-shared temp directory that other tests reuse, or
    /// reopening the lock by path instead of holding the `File`) would
    /// fail this test: either the second acquire would block forever
    /// (and the test would time out) or the reacquire after drop would
    /// fail because the OS-level lock had leaked.
    #[test]
    fn implement_lock_blocks_concurrent_acquire_and_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_path = tmp.path();

        let first = acquire_implement_lock(repo_path).expect("first acquire must succeed");

        // The same process can hold an `flock` exclusive lock only once;
        // an in-process re-acquire on a separately-opened handle must
        // surface the `WouldBlock` translation. The point of the test is
        // that the *operator-facing* error message names the contention
        // (rather than e.g. blocking forever or surfacing an opaque IO
        // error).
        let err = acquire_implement_lock(repo_path)
            .expect_err("second acquire must fail while first lock is held");
        assert!(
            err.contains("in progress"),
            "expected operator-facing contention message, got: {err}",
        );

        drop(first);

        // After the first guard drops the lock is released, so a fresh
        // acquire on the same path must succeed.
        let _second = acquire_implement_lock(repo_path)
            .expect("reacquire must succeed after the first guard drops");
    }
}
