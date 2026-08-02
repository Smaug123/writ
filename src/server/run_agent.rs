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
use std::num::NonZeroUsize;

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

/// How many agent runs writd will execute at once when configuration is silent.
///
/// Two, chosen to be obviously safe rather than tuned: the cost of a run is a
/// child process plus threads (host arm) or a whole VM (VM arm), and no
/// measurement here would generalise across operators' hardware. It is a config
/// key precisely so the number can move without a release.
pub const DEFAULT_MAX_CONCURRENT_AGENT_RUNS: NonZeroUsize = NonZeroUsize::new(2).unwrap();

/// How many agent runs may be *waiting* for a slot before writd stops queueing
/// them, when configuration is silent.
///
/// Generous on purpose: this is not a tuning knob for throughput, it is the
/// depth past which a queue has stopped being a delay and become somewhere
/// requests go to be forgotten. Two readings put it here.
///
/// What a waiting run costs. Each holds a tokio task, an open connection, and
/// its prompt — up to [`MAX_AGENT_PROMPT_BYTES`](crate::agent_run::MAX_AGENT_PROMPT_BYTES),
/// 1 MiB. Sixty-four of them is bounded by roughly 64 MiB and 64 descriptors,
/// which no host writd can run on would notice.
///
/// What a waiting run means. At the default of two concurrent runs, sixty-four
/// queued minutes-long jobs is already many hours of backlog — long past the
/// point where the caller wanted a delay rather than an answer. So the bound is
/// set where it stops describing patience and starts describing a pile-up.
pub const DEFAULT_MAX_PENDING_AGENT_RUNS: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// The bound on how many agent runs may be in flight at once, across *both*
/// dispatch arms — and, separately, on how many more may be waiting to be.
///
/// One bound rather than one per arm. The arms differ in what a run costs — the
/// host arm holds a tokio blocking-pool thread (of 512, shared with notes writes
/// and every other `spawn_blocking` in writd), two OS threads for the stream
/// captures, and a child process; the VM arm holds a VM — but they do not
/// differ in *whose* machine pays, and a per-arm bound would let twice the
/// configured number run.
///
/// **Two bounds, because there are two things to bound.** The concurrency limit
/// says how many runs execute; a caller over it queues, which is the right
/// answer for an agent run — a minutes-long job dispatched by a workflow tool,
/// where a delay beats a failure the caller must build retry logic around.
/// [`tokio::sync::Semaphore`] hands permits out in FIFO order, so "queue" is
/// what waiting on it already means, and a burst cannot starve its own tail.
///
/// But queueing is only a delay while the queue is finite. Nothing bounded the
/// waiters themselves, so a submission rate above throughput grew tasks,
/// connections and buffered prompts without limit, and each caller's wait grew
/// with it — the failure mode being not an error but an unbounded silence. The
/// queue-depth bound is what makes the promise "you will be served" checkable
/// before it is made: over it, `enqueue` refuses **at once**,
/// saying so, rather than admitting a caller to a queue it cannot promise to
/// drain.
///
/// **How the two are counted, and what that buys.** Not as two disjoint
/// populations, which is the obvious implementation and is wrong. The bound
/// writd enforces is on *admission* — running plus waiting, `limit +
/// queue_limit` together — and a run holds its admission for its whole life,
/// execution included. The concurrency limit then decides how many of the
/// admitted may run at a time.
///
/// The guarantee that follows is narrow and worth stating exactly, because two
/// stronger-sounding versions of it are false:
///
/// > **writd refuses a run exactly when it is already holding `limit +
/// > queue_limit` of them.**
///
/// That is one `try_acquire` on one semaphore, so no interleaving can produce a
/// refusal writd's own accounting does not justify. It is *not* the claim that a
/// free permit on the `slots` semaphore implies a free admission: admitted runs
/// that have not yet reached `AgentRunQueuePlace::wait_for_slot` hold admission
/// without yet holding the slots they are about to take, so `available()` can
/// read non-zero at the moment a refusal is issued. Those slots are spoken for,
/// and the refusal is right.
///
/// Two alternatives were tried and are worse, both for the same reason — they
/// split the decision in two, and a decision in two steps is not atomic:
///
/// * Counting waiters in their own semaphore and vacating the place when a slot
///   was granted. A run passing through an *idle* slot still occupied queue
///   depth while in transit, so a small `queue_limit` could refuse a request
///   while execution capacity sat unused.
/// * Reserving the slot inside admission — `try_acquire` the slot, fall back to
///   a queue place. This makes "a free slot is never refused" instantaneously
///   true, but only by taking two permits in sequence: with limits 1 and 1, two
///   requests can both find the slot full, the running run can then finish, the
///   first request takes the sole queue place, and the second is refused with a
///   slot now free. Trading an exact guarantee for a stronger-sounding one that
///   a race can break is the wrong way round.
#[derive(Clone, Debug)]
pub struct AgentRunSlots {
    /// Running plus waiting: `limit + queue_limit` permits, held from
    /// [`Self::enqueue`] until the run ends. This is the bound that refuses.
    admitted: Arc<tokio::sync::Semaphore>,
    /// Running: `limit` permits, taken by
    /// `AgentRunQueuePlace::wait_for_slot` out of the admitted set. This is
    /// the bound that makes callers wait.
    slots: Arc<tokio::sync::Semaphore>,
    limit: NonZeroUsize,
    queue_limit: NonZeroUsize,
}

impl AgentRunSlots {
    /// Build the two bounds, refusing limits the underlying semaphore cannot
    /// hold.
    ///
    /// Fallible only because of that ceiling: [`tokio::sync::Semaphore::new`]
    /// *panics* above [`tokio::sync::Semaphore::MAX_PERMITS`], and a limit is
    /// operator input, so the failure would land as a daemon crash during
    /// startup rather than as a message naming the bad field. No configuration
    /// value should be able to do that.
    ///
    /// The admission semaphore holds the *sum*, so the sum is what has to fit —
    /// two individually representable limits can still add to something that is
    /// not, and `usize` addition would wrap rather than say so.
    pub fn new(limit: NonZeroUsize, queue_limit: NonZeroUsize) -> Result<Self, AgentRunSlotsError> {
        // Each is checked separately first, so the error names *which* field is
        // out of range: one message that could describe either would send an
        // operator to edit the wrong line.
        for (field, value) in [
            ("max_concurrent_agent_runs", limit),
            ("max_pending_agent_runs", queue_limit),
        ] {
            if value.get() > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(AgentRunSlotsError::AboveMaxPermits {
                    field,
                    limit: value,
                    max: tokio::sync::Semaphore::MAX_PERMITS,
                });
            }
        }
        let admitted = limit
            .get()
            .checked_add(queue_limit.get())
            .filter(|total| *total <= tokio::sync::Semaphore::MAX_PERMITS)
            .ok_or(AgentRunSlotsError::TotalAboveMaxPermits {
                limit,
                queue_limit,
                max: tokio::sync::Semaphore::MAX_PERMITS,
            })?;
        Ok(Self {
            admitted: Arc::new(tokio::sync::Semaphore::new(admitted)),
            slots: Arc::new(tokio::sync::Semaphore::new(limit.get())),
            limit,
            queue_limit,
        })
    }

    /// The configured concurrency bound, for tests and operator-facing reporting.
    pub fn limit(&self) -> NonZeroUsize {
        self.limit
    }

    /// The configured queue-depth bound, for tests and operator-facing reporting.
    pub fn queue_limit(&self) -> NonZeroUsize {
        self.queue_limit
    }

    /// How many runs could start right now without waiting.
    ///
    /// A momentary reading, not a reservation — by the time a caller acts on it
    /// the number may have changed, so it is for reporting and for tests, never
    /// for deciding whether to start a run. Tests need it because the property
    /// that matters for a VM run is *when the slot is released*, and a run that
    /// takes a slot and drops it immediately is indistinguishable from one that
    /// holds it if all you can see is that `acquire` was called.
    pub fn available(&self) -> usize {
        self.slots.available_permits()
    }

    /// How many more runs writd would admit right now — running and waiting
    /// counted together, since that is the population the bound is on. The same
    /// momentary reading as [`Self::available`], for the other bound.
    pub fn admission_available(&self) -> usize {
        self.admitted.available_permits()
    }

    /// Admit this run, or refuse it outright.
    ///
    /// Synchronous and immediate by design: the whole point of the bound is that
    /// a caller over it gets an answer now. Refusing is the only thing this
    /// returns that a caller can act on — the alternative writd used to offer
    /// was an unbounded wait, which is indistinguishable from being forgotten.
    ///
    /// **One atomic step**, and that is the whole of the guarantee: a refusal
    /// means writd was already holding `limit + queue_limit` runs at the instant
    /// it decided. No interleaving of concurrent callers can produce a refusal
    /// its own accounting does not justify. See [`AgentRunSlots`] for why this
    /// is deliberately not the stronger "a free slot is never refused", and what
    /// goes wrong when that is attempted.
    ///
    /// Callers must admit *after* validating the request: taking a place only to
    /// answer "that request was malformed" would spend depth on a run that was
    /// never going to happen. Each arm's preconditions differ, so this is not
    /// something the dispatcher can do once on their behalf.
    pub(crate) fn enqueue(&self) -> Result<AgentRunQueuePlace, AgentRunQueueFull> {
        match Arc::clone(&self.admitted).try_acquire_owned() {
            Ok(admission) => Ok(AgentRunQueuePlace {
                admission,
                slots: Arc::clone(&self.slots),
            }),
            Err(tokio::sync::TryAcquireError::NoPermits) => Err(AgentRunQueueFull {
                limit: self.limit,
                queue_limit: self.queue_limit,
            }),
            // Owned by `BrokerState` and never closed, exactly like `slots`.
            Err(tokio::sync::TryAcquireError::Closed) => {
                unreachable!("the agent-run admission semaphore is never closed")
            }
        }
    }
}

impl Default for AgentRunSlots {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_CONCURRENT_AGENT_RUNS,
            DEFAULT_MAX_PENDING_AGENT_RUNS,
        )
        .expect("the built-in defaults are far below the semaphore's ceiling")
    }
}

/// One admitted agent run, before it holds a slot.
///
/// Exists so that a run slot cannot be acquired without first passing the
/// admission bound: [`AgentRunSlots`] has no public way to wait, so the only
/// route to an [`AgentRunSlot`] is through a place obtained from
/// [`AgentRunSlots::enqueue`]. That is the bound made structural rather than
/// remembered — a future caller that forgets it has nothing to call.
///
/// Dropping this without reaching a slot gives the admission back, which is what
/// makes a caller that gives up mid-wait indistinguishable from one that never
/// arrived.
#[derive(Debug)]
pub(crate) struct AgentRunQueuePlace {
    /// This run's claim on the admission bound. Moved into the [`AgentRunSlot`]
    /// when a slot is granted, because the claim covers the run's whole life and
    /// not just the part of it spent waiting.
    admission: tokio::sync::OwnedSemaphorePermit,
    slots: Arc<tokio::sync::Semaphore>,
}

impl AgentRunQueuePlace {
    /// Wait for a slot however long it takes, then hold both it and the
    /// admission until the returned guard is dropped.
    ///
    /// Consumes the place and carries its admission into the slot, so a run
    /// counts against the admission bound from the moment it is accepted to the
    /// moment it ends — waiting and running alike. On the bounded path above,
    /// the timeout drops this future instead, which drops the admission and
    /// leaves the caller having occupied nothing.
    pub(crate) async fn wait_for_slot(self) -> AgentRunSlot {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            // The semaphore is owned by `BrokerState` and never closed;
            // `acquire_owned` fails only on a closed semaphore.
            .expect("the agent-run semaphore is never closed");
        AgentRunSlot {
            _slot: slot,
            _admission: self.admission,
        }
    }
}

/// Why a configured limit was refused.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AgentRunSlotsError {
    #[error(
        "{field} is {limit}, above the maximum this daemon can \
         represent ({max}); a limit that large is not a bound in any case"
    )]
    AboveMaxPermits {
        field: &'static str,
        limit: NonZeroUsize,
        max: usize,
    },
    #[error(
        "max_concurrent_agent_runs ({limit}) and max_pending_agent_runs \
         ({queue_limit}) together exceed the maximum this daemon can represent \
         ({max}); writd bounds the two as one admission count, so it is their \
         sum that has to fit"
    )]
    TotalAboveMaxPermits {
        limit: NonZeroUsize,
        queue_limit: NonZeroUsize,
        max: usize,
    },
}

/// Why an agent run was not queued: writd is already holding as many as it will.
///
/// The one thing a caller can be told about capacity, and deliberately the only
/// one. Once accepted, a run waits for as long as it takes — no caller sets a
/// start deadline any more, because none of them stay to watch. So "writd would
/// not take this" is a complete account of refusal: it is decided immediately,
/// before any ids are handed out, and it means nothing was started and nothing
/// recorded. Retrying later is exactly the right response.
#[derive(Debug, thiserror::Error, Eq, PartialEq, Clone, Copy)]
#[error(
    "writd will not queue this agent run: it is already running up to {limit} \
     and holding {queue_limit} more waiting, which is the configured maximum \
     (max_concurrent_agent_runs = {limit}, max_pending_agent_runs = \
     {queue_limit}). Nothing was started and nothing was recorded — this request \
     failed outright, so retry it later rather than waiting on it."
)]
pub struct AgentRunQueueFull {
    limit: NonZeroUsize,
    queue_limit: NonZeroUsize,
}

/// One in-flight agent run's claim on *both* bounds. Releases both on drop, so
/// every early return frees them together.
///
/// Carrying the admission alongside the slot is what keeps the two counts
/// consistent: a running run is still an admitted run, so it must go on
/// occupying admission until it ends. Bundling them here means there is no way
/// to release one and forget the other — the run's whole claim has exactly one
/// owner and exactly one `Drop`.
///
/// Visible to the agent-VM daemon because a VM run's claim outlives the request
/// that started it: `StartAgentRun` boots a VM and answers immediately, so the
/// claim has to live with the session and be released when the session is torn
/// down, not when the handler returns.
///
/// Both fields are held for their `Drop` and never read; the leading underscores
/// are what says so.
#[derive(Debug)]
pub(crate) struct AgentRunSlot {
    _slot: tokio::sync::OwnedSemaphorePermit,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

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
/// `purpose` is recorded verbatim on the `agent_run` row by both arms.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_agent<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    purpose: crate::agent_run::RunPurpose,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
    workspace: Option<crate::vm_git::AgentVmWorkspaceBootstrap>,
    agent_kind: Option<crate::core::AgentKind>,
    agent_model: Option<String>,
    agent_vm: Option<&Arc<crate::agent_vm_daemon::AgentVmDaemon>>,
) -> ServerMessage {
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
                purpose,
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
    // Agent identity for the row is the *configured* one: this arm spawns one
    // binary, and the operator who chose it is the only party who knows what
    // it is. The session's kind and the request's are both declarations by a
    // caller that cannot see the daemon's configuration, so neither can stand
    // in — taking the row's value from the session would let writd record
    // "Codex ran" while spawning Claude, and bailiff's `--agent` defaults to
    // claude whether or not that is what writd spawns.
    //
    // They must still *agree*, because the session's kind is not inert: it
    // routes credential mints to a GitHub App. A session claiming an identity
    // the daemon cannot run is a caller working from a false picture, so
    // refuse it here rather than let it mint as one agent and run as another.
    let Some(session_agent_kind) = session.agent_kind else {
        return missing_agent_kind_for_registry_response();
    };
    let spawn_agent_kind = spawn_config.agent_kind;
    if session_agent_kind != spawn_agent_kind {
        return ServerMessage::Error {
            message: format!(
                "RunAgent: session {session_id} was opened for {session_agent_kind}, \
                 but this daemon's host-spawn agent is {spawn_agent_kind}; \
                 open the session with the agent writd is configured to run",
            ),
        };
    }
    if let Some(requested) = agent_kind
        && requested != spawn_agent_kind
    {
        return ServerMessage::Error {
            message: format!(
                "RunAgent: agent_kind {requested} is not this daemon's host-spawn \
                 agent ({spawn_agent_kind})",
            ),
        };
    }

    let run_id = AgentRunId::new();

    // Built before the queue, not after it. `AgentProcessPlan::new` rejects a
    // spawn command this daemon cannot run — a configuration error whose answer
    // does not depend on capacity — and a request whose fate is already decided
    // should not wait behind other people's agents to hear it. That wait has no
    // bound on this path, and the runs ahead of it may be VM sessions that only
    // a human ends.
    let plan = match crate::agent_run::AgentProcessPlan::new(
        run_id,
        spawn_config.command.clone(),
        spawn_config.args.iter().map(std::ffi::OsString::from),
    ) {
        // The capture cap matches the envelope cap so the file on disk is
        // exactly what the envelope carries — see
        // `crate::agent_run_envelope`'s note on the two stacking caps.
        Ok(plan) => {
            let plan = plan.with_max_stream_capture_bytes(MAX_RUN_AGENT_STREAM_BYTES as u64);
            // Absent by default, and absent means the run is genuinely
            // unbounded — see `RunAgentDaemonConfig::spawn_timeout_secs`.
            match spawn_config.timeout {
                Some(timeout) => plan.with_timeout(timeout),
                None => plan,
            }
        }
        // No audit row to abandon: nothing has been recorded yet, which is the
        // other half of why this belongs before the queue.
        Err(err) => {
            return ServerMessage::Error {
                message: format!(
                    "RunAgent: agent command {}: {err}",
                    spawn_config.command.display()
                ),
            };
        }
    };

    // Every precondition is settled, so from here the run is going to happen and
    // the only question is when — unless writd is holding as many runs as it
    // will, in which case the answer is that it will not happen, delivered now.
    // This caller can afford to be told: it is holding a connection open, so an
    // error reaches it, where a place in an unbounded queue would not.
    let place = match state.agent_run_slots.enqueue() {
        Ok(place) => place,
        Err(full) => {
            return ServerMessage::Error {
                message: format!("RunAgent: {full}"),
            };
        }
    };

    // Wait for a slot before the audit row rather than after: a row recorded now
    // would claim a run that has not started, and `requested_at` would date the
    // request rather than the run.
    //
    // Unbounded, and that is still right with a queue bound in front of it: a
    // host run ends by itself, so the queue this caller joined drains without
    // anyone intervening. What the bound changed is whether it could be joined,
    // not how long a place in it is worth waiting on.
    //
    // Held until this function returns, which is when the child has exited and
    // its note is written.
    let _slot = place.wait_for_slot().await;

    // The session was open when this request arrived. That wait has no bound, so
    // by now another connection may have closed it — and the caller deserves to
    // hear *that*, not a generic error. `begin_effect` below does refuse a closed
    // session, but it refuses it as an opaque audit failure, so a client that
    // waited minutes would lose the typed `ClosedSession` it could have acted on.
    match state.audit.get_session(session_id) {
        Ok(Some(session)) if session.closed_at.is_none() => {}
        Ok(Some(_)) => return ServerMessage::ClosedSession { session_id },
        Ok(None) => return ServerMessage::UnknownSession { session_id },
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: re-read session {session_id}: {err}"),
            };
        }
    }

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
            agent_kind: spawn_agent_kind,
            prompt: prompt_summary,
            correlation_id: None,
            purpose: Some(purpose),
        }) {
        Ok(recorded) => recorded,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: record agent run: {err}"),
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
        // The agent itself is already killed and reaped by the runner's guard;
        // any process it forked is not, here or on the success path (see
        // `ChildGuard`). The run did not reach a terminal status we can
        // describe, so there is no truthful outcome to record: fabricating one
        // would consume the run
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

    // Write the note, then give the repo the chance to pack itself. Both happen
    // on the one blocking-pool thread: the compaction takes the same per-repo
    // mutex the write just released, so running it here rather than in a second
    // `spawn_blocking` costs no extra pool slot and cannot interleave with
    // another writer of this repo in this process.
    //
    // Compaction is deliberately *after* the write and reported separately.
    // Writ suppresses git's background auto-maintenance in the repos it owns, so
    // this is the only thing that ever packs them; but by the time it runs the
    // envelope is already durable, and a housekeeping failure must not turn a
    // completed agent run into an error response the caller cannot act on.
    let write_result = {
        let notes_repo = Arc::clone(notes_repo);
        tokio::task::spawn_blocking(move || {
            let oid = notes_repo.write_note(&output_ref, &run_id_seed, &envelope_bytes)?;
            Ok::<_, crate::notes_repo::NotesRepoError>((oid, notes_repo.compact_if_needed()))
        })
        .await
    };
    let (output_oid, compaction) = match write_result {
        Ok(Ok(pair)) => pair,
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
    match compaction {
        Ok(crate::notes_repo::CompactionOutcome::Skipped { .. }) => {}
        Ok(crate::notes_repo::CompactionOutcome::Compacted {
            before,
            after,
            trigger,
        }) => {
            // Both readings, because "gc succeeded" and "gc helped" are
            // different claims and only the pair distinguishes them — and the
            // trigger, because which axis fired is the difference between a repo
            // that writes a lot and one that fetches a lot.
            tracing::info!(
                trigger = %trigger,
                loose_objects_before = before.loose_objects.get(),
                loose_objects_after = after.loose_objects.get(),
                packs_before = before.packs.get(),
                packs_after = after.packs.get(),
                "compacted writ's notes repo"
            );
        }
        // A pause an operator should be able to see, because the repo may want
        // packing and is not getting it. Logged every time rather than once, so
        // the condition is visible for as long as it lasts.
        Ok(crate::notes_repo::CompactionOutcome::Deferred { retry_in }) => {
            tracing::info!(
                retry_in_secs = retry_in.as_secs(),
                "deferred compaction of writ's notes repo after a recent failure"
            );
        }
        // Worth an operator's attention rather than silence: this is the only
        // thing that packs the repo, so a failure that persists means the loose
        // objects grow without bound.
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not compact writ's notes repo; loose objects will keep accumulating"
            );
        }
    }

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
    purpose: crate::agent_run::RunPurpose,
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

    // No slot is taken here, deliberately. Every VM run — this arm's and
    // `StartAgentRun`'s — goes through `start_agent_run_session`, which acquires
    // one and hands it to the running session, so the slot is released when the
    // VM is torn down rather than when a request handler returns. That matters
    // because `StartAgentRun` answers as soon as the VM is up and the session
    // outlives its request entirely.
    //
    // Acquiring again here would be worse than redundant: this arm would hold
    // two slots for one run, and at the default limit of two a single request
    // would exhaust the bound and then wait forever for the slot it is itself
    // blocking.
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
            // The VM arm carries no correlation id: `RunAgent` has no such
            // field. The two tags come from different RPCs, which is what
            // `AgentRunTags` makes explicit at each call site.
            crate::agent_vm_daemon::AgentRunTags {
                correlation_id: None,
                purpose: Some(purpose),
            },
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

/// Handle a [`ClientMessage::VerifyAgentRun`]: say whether writ's own audit
/// log corroborates a signed note.
///
/// The order is load-bearing. The signature is checked first, and a note that
/// fails it returns that verdict *alone*: unverified metadata is unattributed
/// bytes, so comparing its fields against the log would produce findings that
/// look like evidence about a run while being evidence about nothing.
///
/// Only then is the run looked up. The output side of the comparison is not
/// taken from the caller at all — the caller sends no output bytes — but
/// re-derived here by rebuilding the envelope from the stream files the
/// outcome row names, through the same
/// [`crate::agent_run_envelope`] path that signed it in the first place.
/// That path re-checks those files against the row as it reads them, so a
/// stream file altered since the run refuses here rather than quietly
/// producing a digest that then "disagrees" with the note.
pub(super) async fn verify_agent_run<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    signed_metadata: &crate::protocol::SignedRunMetadata,
    signature: &crate::core::SshSignature,
) -> ServerMessage {
    let Some(signing_key) = state.signing_key.clone() else {
        return run_agent_not_configured("signing_key");
    };
    let verdict = match check_signature_is_ours(&signing_key, signed_metadata, signature) {
        Ok(()) => audited_verdict(state, signed_metadata, &signing_key).await,
        Err(verdict) => Ok(verdict),
    };
    match verdict {
        Ok(verdict) => ServerMessage::AgentRunProvenance { verdict },
        Err(message) => ServerMessage::Error { message },
    }
}

/// Refuse a note this daemon did not sign, distinguishing "not ours" from
/// "ours but altered" — the first is the ordinary answer when a note is shown
/// to the wrong writ, the second is tampering.
fn check_signature_is_ours(
    signing_key: &crate::signing::WritSigningKey,
    signed_metadata: &crate::protocol::SignedRunMetadata,
    signature: &crate::core::SshSignature,
) -> Result<(), crate::run_provenance::RunProvenanceVerdict> {
    use crate::run_provenance::RunProvenanceVerdict;

    let ours = signing_key.fingerprint();
    if signed_metadata.signing_key_fingerprint != ours {
        return Err(RunProvenanceVerdict::NotOurs {
            fingerprint: signed_metadata.signing_key_fingerprint.clone(),
        });
    }
    signing_key
        .verifying_key()
        .verify(&signed_metadata.canonical_bytes(), signature)
        .map_err(|_| RunProvenanceVerdict::SignatureInvalid)
}

/// The audit half: load the run's rows and compare them with the note.
async fn audited_verdict<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    signed_metadata: &crate::protocol::SignedRunMetadata,
    signing_key: &crate::signing::WritSigningKey,
) -> Result<crate::run_provenance::RunProvenanceVerdict, String> {
    use crate::run_provenance::{AuditedRun, RunProvenanceVerdict, cross_check};

    let run_id = signed_metadata.run_id;
    let request = state
        .audit
        .get_agent_run(run_id)
        .map_err(|err| format!("VerifyAgentRun: read agent run {run_id}: {err}"))?;
    let Some(request) = request else {
        return Ok(RunProvenanceVerdict::UnknownRun { run_id });
    };
    let outcome = state
        .audit
        .get_agent_run_outcome(run_id)
        .map_err(|err| format!("VerifyAgentRun: read agent run outcome {run_id}: {err}"))?;
    let Some(outcome) = outcome else {
        return Ok(RunProvenanceVerdict::OutcomePending { run_id });
    };

    // Rebuild the envelope from writ's own files to get the digest to compare
    // against. `capabilities` and `prompt_sha256` are echoed from the note
    // here because the materialiser needs them to build metadata it will not
    // be asked for — only `output_envelope_sha256` is read back out, and that
    // comes from the files.
    let materialised = crate::agent_run_envelope::materialize_signed_run_envelope(
        &outcome,
        request.session_id,
        signed_metadata.prompt_sha256.clone(),
        signed_metadata.capabilities.clone(),
        signing_key,
    )
    .await
    .map_err(|err| format!("VerifyAgentRun: re-derive output envelope for {run_id}: {err}"))?;

    let audited = AuditedRun {
        request,
        outcome,
        output_envelope_sha256: materialised.envelope.metadata.output_envelope_sha256,
    };
    Ok(RunProvenanceVerdict::Checked {
        run_id,
        findings: cross_check(signed_metadata, &audited),
    })
}
