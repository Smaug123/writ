//! Run-agent orchestration: the `RunAgent` request handler and its two
//! dispatch arms.
//!
//! [`run_agent`] is dispatched from [`super::dispatch_message_with_agent_vm`].
//! It either spawns the configured child here on the host (via
//! [`crate::agent_run::run_agent_process`]) or opens a per-run agent VM and
//! waits for the guest's outcome. The arms differ in *who runs the agent* and
//! *who owns the audit session*, and in nothing else: both record an
//! `(agent_run, agent_run_outcome)` pair, and both finish through
//! [`sign_and_store_run`], so the signed note a verifier fetches means the
//! same thing either way.
//!
//! Transport and the staged-push subsystem live in the parent [`super`]
//! module. Tests drive this through `dispatch_message` rather than calling in
//! directly.

use super::*;

/// Total wall-clock budget the VM dispatch arm gives a per-run VM
/// agent to complete and POST its outcome to writd. Implementer runs
/// can be long — the bailiff CLI's flock acceptance message already
/// pins "30-minute hold per implement" — so the writd-side wait must
/// be at least as generous as the operator's mental model. A run that
/// blows past this is almost always a stuck guest, not a slow agent;
/// the wait helper returns a structured `Timeout` so the caller
/// surface names both the run id and the elapsed duration.
const RUN_AGENT_VM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// How often the wait helper polls the audit table for the outcome
/// row. 500ms keeps the audit handle warm without spinning; the row
/// arrives within one POST round-trip after the guest finishes, so
/// the observed latency from "outcome lands" to "wait returns" is
/// bounded by this interval rather than the full timeout.
const RUN_AGENT_VM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

fn run_agent_not_configured(component: &str) -> ServerMessage {
    ServerMessage::Error {
        message: format!(
            "RunAgent dispatch is not configured: {component} is unset; \
             writd needs notes_repo + signing_key + run_agent_spawn to serve RunAgent"
        ),
    }
}

/// Handle a [`ClientMessage::RunAgent`] request end-to-end.
///
/// Record the run in the audit log, spawn the configured child with the
/// prompt on stdin, capture both streams to files under the configured
/// log root, record the outcome, sign the resulting
/// [`SignedRunMetadata`](crate::protocol::SignedRunMetadata), wrap
/// everything in a [`SignedRunEnvelope`](crate::run_envelope::SignedRunEnvelope),
/// and store the envelope in writ's own bare repo under `output_ref`
/// keyed on the run id.
/// The on-the-wire `output_ref` is a ref name inside writ's repo
/// (bailiff fetches `refs/notes/writ/v1/*` over Git remote, per the
/// cross-daemon ownership decision pinned in
/// `docs/plans/2026-05-14-bailiff-split.md`); the request does **not**
/// name a filesystem path.
///
/// `capabilities` is recorded verbatim into the signed metadata so a
/// verifier sees the full set the run was authorised under.
/// Capability-set policy enforcement (refusing to spawn if a granted
/// variant is denied by `policy::*`) is deferred to a follow-up slice —
/// see the plan doc.
///
/// `purpose` is still not recorded: the `agent_run` table has no column
/// for it and `correlation_id` cannot stand in (its charset rejects
/// bailiff's `review:plan-abc`), so recording it needs a schema
/// migration of its own.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_agent<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    purpose: String,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
    workspace: Option<crate::vm_git::AgentVmWorkspaceBootstrap>,
    agent_kind: Option<crate::core::AgentKind>,
    agent_model: Option<String>,
    agent_vm: Option<&Arc<crate::agent_vm_daemon::AgentVmDaemon>>,
) -> ServerMessage {
    // `purpose` is part of the wire contract and lands on the audit row once
    // the column exists. Holding the name in scope (not discarding via `_`)
    // keeps the pending plumbing self-evident.
    let _purpose = purpose;

    // VM1 invariant: a `WorkspaceWrite` capability is only meaningful
    // when the request also carries a workspace bootstrap, because the
    // host-spawn path has no cwd for the agent to mutate. Reject the
    // lie before any state work happens — an unconfigured broker still
    // fails here rather than masking the gate with a not-configured
    // message. When `workspace` is `Some`, route to the per-run VM
    // dispatch; the host-spawn path below is for read-only or
    // prompt-only runs that have no checkout to operate on.
    let needs_workspace = capabilities
        .iter()
        .any(|c| matches!(c, crate::core::CapabilitySet::WorkspaceWrite { .. }));
    match (needs_workspace, workspace) {
        (true, None) => {
            return ServerMessage::Error {
                message: "RunAgent: WorkspaceWrite capability requires a workspace bootstrap"
                    .into(),
            };
        }
        (_, Some(ws)) => {
            return run_agent_in_vm(
                state,
                agent_vm,
                prompt,
                capabilities,
                output_ref,
                request_session_id,
                ws,
                agent_kind,
                agent_model,
            )
            .await;
        }
        (false, None) => {}
    }

    let Some(notes_repo) = state.notes_repo.clone() else {
        return run_agent_not_configured("notes_repo");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return run_agent_not_configured("signing_key");
    };
    let Some(spawn_config) = state.run_agent_spawn.clone() else {
        return run_agent_not_configured("run_agent_spawn");
    };

    // The host-spawn arm requires an open audit session, because the run it
    // is about to perform must be recorded and an `agent_run` row's
    // `session_id` is a foreign key onto `session`. It used to accept `None`
    // and mint a `SessionId` that was never opened, stamping it into the
    // signed envelope — an envelope claiming a session no verifier could
    // resolve. Reject unknown / already-closed sessions before we spawn, for
    // the same reason.
    let Some(session_id) = request_session_id else {
        return ServerMessage::Error {
            message: "RunAgent: host-spawn dispatch requires session_id; \
                      open a session first so the run can be recorded against it"
                .into(),
        };
    };
    let session = match state.audit.get_session(session_id) {
        Ok(Some(session)) if session.closed_at.is_none() => session,
        Ok(Some(_)) => return ServerMessage::ClosedSession { session_id },
        Ok(None) => return ServerMessage::UnknownSession { session_id },
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: read session {session_id}: {err}"),
            };
        }
    };
    // Agent identity for the row comes from the session, which is where the
    // caller fixed it at `OpenSession`; the host arm has no per-run identity
    // of its own. The request's `agent_kind` is therefore redundant here —
    // but a *contradictory* one would have the row say Claude while the
    // caller believes it asked for Codex, so refuse rather than silently
    // prefer one.
    let Some(session_agent_kind) = session.agent_kind else {
        return missing_agent_kind_for_registry_response();
    };
    if let Some(requested) = agent_kind
        && requested != session_agent_kind
    {
        return ServerMessage::Error {
            message: format!(
                "RunAgent: agent_kind {requested} contradicts session {session_id}, \
                 which was opened for {session_agent_kind}; \
                 host-spawn runs take their agent identity from the session",
            ),
        };
    }

    let run_id = AgentRunId::new();
    let prompt_summary = prompt.summary();
    let prompt_sha256 = Sha256Hex::try_new(prompt_summary.sha256_hex.clone())
        .expect("AgentPrompt::summary hashes via sha256_hex");

    // Two-phase, request row first: the row commits before the child starts,
    // so a run interrupted by a crash is visible as an unpaired request rather
    // than as nothing at all. The VM arm records its row at launch for the
    // same reason. Every path below either `complete`s the guard with a
    // truthful outcome or `abandon`s it.
    let recorded = match state
        .audit
        .begin_effect::<crate::audit::AgentRunAuditTable>(&crate::audit::AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::now(),
            agent_kind: session_agent_kind,
            prompt: prompt_summary,
            correlation_id: None,
        }) {
        Ok(recorded) => recorded,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: record agent run: {err}"),
            };
        }
    };

    let plan = match crate::agent_run::AgentProcessPlan::new(
        run_id,
        spawn_config.command.clone(),
        spawn_config.args.iter().map(std::ffi::OsString::from),
    ) {
        // The capture cap matches the envelope cap so the file on disk is
        // exactly what the envelope carries — see
        // `crate::agent_run_envelope`'s note on the two stacking caps.
        Ok(plan) => plan.with_max_stream_capture_bytes(MAX_RUN_AGENT_STREAM_BYTES as u64),
        Err(err) => {
            recorded.abandon();
            return ServerMessage::Error {
                message: format!(
                    "RunAgent: agent command {}: {err}",
                    spawn_config.command.display()
                ),
            };
        }
    };

    // `run_agent_process` is blocking (it spawns, writes the prompt, and joins
    // two capture threads), so it goes to the blocking pool rather than
    // stalling this reactor thread for the length of an agent run.
    //
    // **What one in-flight host run costs**, since agent runs are long and
    // this arm has no timeout of its own (`RUN_AGENT_VM_TIMEOUT` bounds only
    // the VM arm): one thread from tokio's blocking pool — 512 by default,
    // shared with every other `spawn_blocking` in the daemon, including the
    // notes write below — plus the two OS threads the helper uses for the
    // captures, plus the child, all for the run's full duration. So N
    // concurrent host runs hold N of those 512 and 2N OS threads, and a hung
    // agent holds its share until the daemon restarts.
    //
    // Nothing bounds N. That is not new — nothing bounded concurrent
    // `RunAgent` calls on either arm before this either, and the previous
    // async spawn held tokio tasks instead — but the resource is now a capped
    // shared pool rather than the scheduler, so the ceiling is closer.
    // Bounding it properly needs a concurrency policy for agent runs (a limit,
    // a queue discipline, and a wire answer for "too many in flight") that
    // covers both arms; tracked separately rather than guessed at here.
    let log_root = spawn_config.log_root.as_path().to_path_buf();
    let captured = tokio::task::spawn_blocking(move || {
        crate::agent_run::run_agent_process(&plan, &prompt, &log_root)
    })
    .await;
    let capture = match captured {
        Ok(Ok(capture)) => capture,
        // The run did not reach a terminal status we can describe, so there is
        // no truthful outcome to record: fabricating one would consume the run
        // id's only outcome slot with a lie. Leave the request row unpaired,
        // which is what an unfinished run looks like. Note that the generic
        // boot scan does *not* range over `agent_run` (an unpaired row there
        // is indistinguishable from a run still in flight, so it would
        // false-positive on every live run) — resolving these belongs to the
        // agent-run lifecycle.
        Ok(Err(err)) => {
            recorded.abandon();
            return ServerMessage::Error {
                message: format!(
                    "RunAgent: run agent {}: {err}",
                    spawn_config.command.display()
                ),
            };
        }
        Err(err) => {
            recorded.abandon();
            return ServerMessage::Error {
                message: format!("RunAgent: agent run task failed: {err}"),
            };
        }
    };

    let outcome = crate::audit::AgentRunOutcomeAuditRecord {
        completed_at: UnixMillis::now(),
        outcome: capture.to_outcome(),
    };
    // Record the outcome before signing: the row is writ's record of what
    // happened, the note is an artefact derived from it. A note signed
    // against an outcome the log never accepted would be the one ordering
    // that leaves the two disagreeing.
    if let Err(err) = recorded.complete(&outcome) {
        return ServerMessage::Error {
            message: format!("RunAgent: record agent run outcome: {err}"),
        };
    }

    sign_and_store_run(
        &notes_repo,
        &signing_key,
        &outcome,
        session_id,
        prompt_sha256,
        capabilities,
        output_ref,
    )
    .await
}

/// Sign a finished run's envelope and store it in writ's notes repo, the tail
/// both `RunAgent` arms share once their outcome row is recorded.
///
/// Shared so the two arms cannot drift: an envelope's meaning must not depend
/// on whether the agent ran on the host or in a guest, and the note layout a
/// verifier fetches is part of that. Returns the wire response directly —
/// either `RunAgentCompleted` or the `Error` describing which step failed.
async fn sign_and_store_run(
    notes_repo: &Arc<crate::notes_repo::NotesRepo>,
    signing_key: &crate::signing::WritSigningKey,
    outcome: &crate::audit::AgentRunOutcomeAuditRecord,
    session_id: SessionId,
    prompt_sha256: Sha256Hex,
    capabilities: Vec<crate::core::CapabilitySet>,
    output_ref: NotesRef,
) -> ServerMessage {
    let materialised = match crate::agent_run_envelope::materialize_signed_run_envelope(
        outcome,
        session_id,
        prompt_sha256,
        capabilities,
        signing_key,
    )
    .await
    {
        Ok(materialised) => materialised,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: materialise signed envelope: {err}"),
            };
        }
    };

    // Seed the note's target OID with the run id bytes so each run gets
    // a distinct attachment object. The seed carries no payload — the
    // signed envelope itself lives in the note body, per the slice-B
    // durability decision (envelope in body, not a separate blob).
    let run_id_seed = outcome.outcome.run_id.to_string().into_bytes();
    let envelope_bytes = materialised.envelope_bytes;
    let metadata = materialised.envelope.metadata;
    let signature = materialised.envelope.signature;

    let write_result = {
        let notes_repo = Arc::clone(notes_repo);
        tokio::task::spawn_blocking(move || {
            notes_repo.write_note(&output_ref, &run_id_seed, &envelope_bytes)
        })
        .await
    };
    let output_oid = match write_result {
        Ok(Ok(oid)) => oid,
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("RunAgent: write signed-run note: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: notes-write task failed: {err}"),
            };
        }
    };

    ServerMessage::RunAgentCompleted {
        output_oid,
        signed_metadata: metadata,
        signature,
    }
}

/// VM dispatch arm for [`ClientMessage::RunAgent`]: open a per-run agent
/// VM via [`AgentVmDaemon::start_agent_run_session`], wait for the
/// guest's outcome row to land, materialise the signed envelope from
/// the on-disk streams, and persist it to writ's notes repo.
///
/// The arm is structurally distinct from the host-spawn path:
/// * `session_id` is *minted by the VM lifecycle* (the agent VM opens
///   its own audit session). A caller that passes `session_id: Some(_)`
///   alongside a `workspace` bootstrap is asking for two contradictory
///   session bindings; reject up front rather than silently ignoring
///   one.
/// * `agent_kind` and `agent_model` must both be present — the VM
///   lifecycle needs them to record the agent_run row and to build the
///   guest command. The host path tolerates them being absent because
///   it doesn't open an audit session; the VM path cannot.
/// * The 30-minute timeout matches bailiff's flock "30-minute hold per
///   implement" message so the operator's mental model matches reality
///   on both sides.
///
/// The envelope materialiser is pure-with-IO: no audit writes, no
/// network. This arm assembles the surrounding context (configuration
/// checks, prompt hashing, lifecycle start, wait, notes-repo write)
/// and returns the same `RunAgentCompleted` wire variant the host path
/// returns, so a verifier consumes both shapes uniformly.
#[allow(clippy::too_many_arguments)]
async fn run_agent_in_vm<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    agent_vm: Option<&Arc<crate::agent_vm_daemon::AgentVmDaemon>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
    workspace: crate::vm_git::AgentVmWorkspaceBootstrap,
    agent_kind: Option<crate::core::AgentKind>,
    agent_model: Option<String>,
) -> ServerMessage {
    if request_session_id.is_some() {
        return ServerMessage::Error {
            message: "RunAgent: VM mode mints its own audit session; \
                      caller must not supply session_id alongside a workspace bootstrap"
                .into(),
        };
    }

    let Some(agent_vm) = agent_vm else {
        return ServerMessage::Error {
            message: "RunAgent: agent VM runtime is not configured; \
                      the broker config needs an agent_vm.vm_http section"
                .into(),
        };
    };
    let Some(agent_kind) = agent_kind else {
        return ServerMessage::Error {
            message: "RunAgent: VM mode requires agent_kind".into(),
        };
    };
    let Some(agent_model) = agent_model else {
        return ServerMessage::Error {
            message: "RunAgent: VM mode requires agent_model".into(),
        };
    };

    let Some(notes_repo) = state.notes_repo.clone() else {
        return run_agent_not_configured("notes_repo");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return run_agent_not_configured("signing_key");
    };

    let prompt_bytes = prompt.as_bytes().to_vec();
    let prompt_sha256_str = sha256_hex(&prompt_bytes);
    let prompt_sha256 = Sha256Hex::try_new(prompt_sha256_str)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");

    let started = match agent_vm
        .start_agent_run_session(
            Arc::clone(state),
            None,
            agent_kind,
            agent_model,
            workspace,
            prompt,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(err) => {
            // Start failed: the lifecycle never registered a managed
            // VM (the `Err` arm of `start_agent_run_session` already
            // closes the audit session on failure), so there's
            // nothing to tear down here.
            return ServerMessage::Error {
                message: format!("RunAgent: start agent VM run: {err}"),
            };
        }
    };

    let session_id = started.session_id();
    let run_id = started.run_id();

    // After `start_agent_run_session` returns Ok, the VM is live with
    // an open audit session and broker token. Every return path below
    // must funnel through `stop_session` so a completed (or
    // timed-out) run can't leave a guest holding broker authority
    // until daemon restart. This is the trust-boundary invariant the
    // VM design rests on: a finished run is no longer authorised.
    let response = run_agent_in_vm_after_start(
        &state.audit,
        &notes_repo,
        &signing_key,
        session_id,
        run_id,
        prompt_sha256,
        capabilities,
        output_ref,
    )
    .await;

    if let Err(err) = agent_vm.stop_session(state, session_id).await {
        tracing::error!(
            session_id = %session_id,
            run_id = %run_id,
            error = %err,
            "stop agent VM session after RunAgent dispatch failed",
        );
        // A successful envelope is moot if the guest is still
        // authorised: the trust boundary says "a finished RunAgent
        // returns a guest with no live broker authority." Surface the
        // cleanup failure as an Error so the caller can't read
        // `RunAgentCompleted` as a clean shutdown — the signed note
        // is still on disk for the operator to retrieve via audit,
        // but the wire response no longer asserts a fully-torn-down
        // run. Operator action is required: daemon reconcile (or
        // restart) will clean up the dangling session/state.
        return ServerMessage::Error {
            message: format!(
                "RunAgent: stop agent VM session {session_id} (run {run_id}) failed: {err}; \
                 the managed VM may still hold broker authority — operator action required",
            ),
        };
    }

    response
}

/// Post-start half of the VM dispatch arm: wait for the guest's
/// outcome row, materialise the signed envelope, write the note.
///
/// Split out so the caller can wrap every return path with a single
/// `stop_session` cleanup — the trust-boundary invariant is that a
/// finished `RunAgent` returns a guest with no live broker authority
/// regardless of which step inside the dispatch arm produced the
/// error.
#[allow(clippy::too_many_arguments)]
async fn run_agent_in_vm_after_start(
    audit: &crate::audit::AuditLog,
    notes_repo: &Arc<crate::notes_repo::NotesRepo>,
    signing_key: &crate::signing::WritSigningKey,
    session_id: SessionId,
    run_id: AgentRunId,
    prompt_sha256: Sha256Hex,
    capabilities: Vec<crate::core::CapabilitySet>,
    output_ref: NotesRef,
) -> ServerMessage {
    let outcome = match crate::agent_vm_daemon::wait_for_agent_run_outcome(
        audit,
        run_id,
        RUN_AGENT_VM_TIMEOUT,
        RUN_AGENT_VM_POLL_INTERVAL,
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: wait for agent VM outcome: {err}"),
            };
        }
    };

    sign_and_store_run(
        notes_repo,
        signing_key,
        &outcome,
        session_id,
        prompt_sha256,
        capabilities,
        output_ref,
    )
    .await
}
