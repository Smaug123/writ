//! The `AgentVmDaemon` method surface: session start/stop/reconcile
//! orchestration and its network-health, broker-VM, and cleanup helpers.
//!
//! This is one inherent `impl AgentVmDaemon` block, split out of
//! `agent_vm_daemon.rs` to keep the daemon's runtime-config/report types and
//! free functions legible separately. The struct itself and everything the
//! methods reference (config/report types, the `choose_subnet_index` and
//! `*_url_for_broker_url` free functions, the guest_command/materialize/
//! run_outcome submodules) stay in the parent module and are reached via
//! `super`. Behaviour is unchanged.

use super::*;

impl AgentVmDaemon {
    pub fn new(config: AgentVmDaemonRuntimeConfig) -> Self {
        Self {
            config,
            running: Mutex::new(HashMap::new()),
            subnet_allocation_lock: Mutex::new(()),
            session_locks: Mutex::new(HashMap::new()),
            network_health: Arc::new(std::sync::Mutex::new(HashMap::new())),
            health_monitor: std::sync::Mutex::new(None),
            vm_broker_attached: Mutex::new(HashMap::new()),
        }
    }

    /// Spawn the daemon-lifetime network-health monitor if it is not already
    /// running. Called on the first session start, when an [`AuditLog`] handle
    /// is available. The monitor inspects only the host's own interfaces; it
    /// never probes the untrusted guest.
    fn ensure_network_health_monitor(&self, audit: Arc<AuditLog>) {
        let mut guard = self.health_monitor.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_network_health_monitor(
            self.config.lifecycle.state_store.clone(),
            self.config.lifecycle.pool,
            Arc::clone(&self.network_health),
            audit,
            NETWORK_HEALTH_PROBE_INTERVAL,
            shutdown_rx,
            host_interfaces,
        ));
        *guard = Some(NetworkHealthMonitorHandle {
            shutdown: shutdown_tx,
            task,
        });
    }

    async fn session_lock_handle(&self, session_id: SessionId) -> Arc<Mutex<()>> {
        let mut locks = self.session_locks.lock().await;
        Arc::clone(
            locks
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Drops the per-session lock map entry if no task is holding or waiting
    /// for it. Caller must have already dropped its own [`Arc`] handle so the
    /// strong count reflects only the map's own reference.
    async fn drop_idle_session_lock(&self, session_id: SessionId) {
        let mut locks = self.session_locks.lock().await;
        if let Some(lock) = locks.get(&session_id)
            && Arc::strong_count(lock) == 1
        {
            locks.remove(&session_id);
        }
    }

    /// How many per-session lock entries are currently registered.
    ///
    /// For tests. The map is an implementation detail with no operator meaning,
    /// but "does a refused start leave one behind" is not observable any other
    /// way, and the answer used to be yes.
    #[cfg(test)]
    pub(crate) async fn session_lock_count(&self) -> usize {
        self.session_locks.lock().await.len()
    }

    pub fn config(&self) -> &AgentVmDaemonRuntimeConfig {
        &self.config
    }

    pub async fn start_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        label: Option<String>,
        agent_kind: Option<AgentKind>,
        agent_model: Option<String>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // The lower lifecycle layer keeps dual-stack manual starts compatible
        // with image defaults. The daemon API is stricter: the host protocol
        // should say exactly what the authority-bearing guest will execute.
        if guest_command.is_empty() {
            return Err(AgentVmDaemonError::EmptyGuestCommand);
        }

        let session_id = SessionId::new();
        let session_lock = self.session_lock_handle(session_id).await;
        let outcome = async {
            let _session_guard = session_lock.lock().await;
            state.audit.open_session(&SessionRecord {
                session_id,
                label,
                agent_kind,
                agent_model,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })?;

            let start_result = async {
                if let Some(workspace) = workspace.as_ref() {
                    let record = workspace_bootstrap_audit_record(session_id, workspace)?;
                    state.audit.record_agent_vm_workspace_bootstrap(&record)?;
                }
                self.start_session_after_audit_opened(
                    Arc::clone(&state),
                    session_id,
                    agent_kind,
                    workspace,
                    guest_command,
                    None,
                    None,
                )
                .await
            }
            .await;

            start_result.map_err(|err| {
                close_audit_session_best_effort(&state, session_id);
                AgentVmDaemonError::StartFailed {
                    session_id,
                    source: Box::new(err),
                }
            })
        }
        .await;

        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_agent_run_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        label: Option<String>,
        agent_kind: AgentKind,
        agent_model: String,
        workspace: AgentVmWorkspaceBootstrap,
        prompt: AgentPrompt,
        tags: AgentRunTags,
        // How long this caller will wait for a slot. Not a property of the
        // daemon: `StartAgentRun`'s client has a deadline and goes away,
        // `RunAgent`'s holds the connection for the whole run.
        queueing: crate::server::AgentRunQueueing,
    ) -> Result<AgentRunStarted, AgentVmDaemonError> {
        let session_id = SessionId::new();
        let run_id = AgentRunId::new();
        // Everything that can refuse this request happens before the per-session
        // lock is registered, so a refusal leaves nothing behind. Session ids are
        // fresh UUIDs that no later request reuses, so an entry added for a start
        // that never happened is never collected — the map would grow by one per
        // rejection for the daemon's lifetime.
        //
        // Answers this request already has come first, before it can be made to
        // wait for one it does not. Both were previously discovered *after* the
        // slot was acquired, so at capacity a request whose fate was already
        // decided — a malformed workspace destination, or an agent run under a
        // broker placement that cannot serve one — would queue behind other
        // people's agents before being told what was wrong with it.
        //
        // Recomputed rather than threaded onward: the checks are cheap and pure,
        // and a second call cannot disagree with the first.
        if let BrokerPlacement::Vm = self.config.lifecycle.broker_placement {
            return Err(AgentVmDaemonError::StartFailed {
                session_id,
                source: Box::new(AgentVmDaemonError::AgentRunUnsupportedForVmBroker),
            });
        }
        workspace_bootstrap_audit_record(session_id, &workspace).map_err(|source| {
            AgentVmDaemonError::StartFailed {
                session_id,
                source: Box::new(source),
            }
        })?;

        // Before the audit session is opened, and before any VM work: a queued
        // run has not started, and an open session with no VM behind it would
        // claim otherwise. `StartAgentRun` answers as soon as the VM is up, so
        // this slot cannot live in this function's scope — it is handed to the
        // running session below and released when that session is torn down.
        //
        // The queue place comes first and is refused synchronously: a run writd
        // will not queue should learn so now, in the same breath as the
        // malformed-request answers above, rather than after a wait.
        let place = state
            .agent_run_slots
            .enqueue()
            .map_err(AgentVmDaemonError::AgentRunQueueFull)?;

        // Whether this wait is bounded is the caller's call, not ours — see
        // `AgentRunQueueing`. Both kinds of caller reach this one function, and
        // they differ in whether anyone is still listening when the wait ends.
        let run_slot = match place.wait_for_slot_with(queueing).await {
            Ok(slot) => slot,
            // The budget comes back from the wait itself rather than being named
            // again here, so this cannot report a duration the caller did not
            // actually wait.
            Err(waited) => {
                return Err(AgentVmDaemonError::AgentRunsAtCapacity {
                    limit: state.agent_run_slots.limit().get(),
                    waited,
                });
            }
        };

        let session_lock = self.session_lock_handle(session_id).await;
        let outcome = async {
            let _session_guard = session_lock.lock().await;
            state.audit.open_session(&SessionRecord {
                session_id,
                label,
                agent_kind: Some(agent_kind),
                agent_model: Some(agent_model.clone()),
                opened_at: UnixMillis::now(),
                closed_at: None,
            })?;

            let start_result = async {
                let workspace_record = workspace_bootstrap_audit_record(session_id, &workspace)?;
                state
                    .audit
                    .record_agent_vm_workspace_bootstrap(&workspace_record)?;
                state.audit.record_agent_run(&AgentRunAuditRecord {
                    run_id,
                    session_id,
                    requested_at: UnixMillis::now(),
                    agent_kind,
                    prompt: prompt.summary(),
                    correlation_id: tags.correlation_id.clone(),
                    purpose: tags.purpose.clone(),
                })?;
                let agent_runs = VmHttpAgentRunService::new(
                    Arc::clone(&state),
                    self.config.agent_run_log_root(),
                );
                agent_runs.insert_run_config(run_id, prompt.clone(), agent_model.clone());
                let guest_command =
                    build_agent_run_guest_command(agent_kind, run_id, workspace.warm);
                self.start_session_after_audit_opened(
                    Arc::clone(&state),
                    session_id,
                    Some(agent_kind),
                    Some(workspace),
                    guest_command,
                    Some(agent_runs),
                    Some(run_slot),
                )
                .await
            }
            .await;

            start_result
                .map(|started| AgentRunStarted {
                    session_id: started.session_id(),
                    run_id,
                    broker_url: started.broker_url().to_string(),
                })
                .map_err(|err| {
                    close_audit_session_best_effort(&state, session_id);
                    AgentVmDaemonError::StartFailed {
                        session_id,
                        source: Box::new(err),
                    }
                })
        }
        .await;

        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        outcome
    }

    pub async fn stop_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        let session_lock = self.session_lock_handle(session_id).await;
        let _session_guard = session_lock.lock().await;

        let result = self.stop_session_locked(state, session_id).await;

        drop(_session_guard);
        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        result
    }

    /// Run the blocking VM/firewall/network teardown for `session_id` on a
    /// blocking thread. The nested result preserves the join-vs-manager
    /// distinction the reconcile sweep maps onto its per-stage error; the
    /// stop/cleanup paths flatten it with `??`.
    ///
    /// Teardown only. Removing the per-session material dir (copied secrets) is
    /// a separate [`Self::spawn_remove_broker_material`] step the callers run
    /// once this confirms the broker VM — which mounts the material read-only —
    /// is gone, so its failure can keep the state record for retry instead of
    /// being swallowed here.
    async fn spawn_cleanup_session(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), AgentVmSessionManagerError>, tokio::task::JoinError> {
        let store = self.config.lifecycle.state_store.clone();
        let tools = self.config.lifecycle.tools.clone();
        tokio::task::spawn_blocking(move || {
            cleanup_managed_agent_vm_session(&store, session_id, tools)
        })
        .await
    }

    /// Run [`Self::spawn_cleanup_session`], flattening the join result and the
    /// inner teardown result into one error type.
    async fn run_cleanup_session(&self, session_id: SessionId) -> Result<(), AgentVmDaemonError> {
        match self.spawn_cleanup_session(session_id).await {
            Ok(inner) => inner.map_err(Into::into),
            Err(join) => Err(join.into()),
        }
    }

    /// The root under which each session's broker-VM host material lives
    /// (`<state_dir>/broker-vm/<session_id>/…`). Derived from the state directory
    /// so the start arm (which writes the material) and stop/reconcile (which
    /// remove it via [`Self::spawn_remove_broker_material`]) agree without extra
    /// configuration.
    fn broker_material_root(&self) -> PathBuf {
        self.config.lifecycle.state_store.dir().join("broker-vm")
    }

    /// Spawn a log tail for a broker VM, pointed at its mirrored log file on the
    /// shared session mount. Used at start, and to re-attach when a stop/cleanup
    /// fails with the broker VM (and its log) still live.
    fn spawn_broker_log_forwarder(&self, session_id: SessionId) -> BrokerLogForwarder {
        BrokerLogForwarder::spawn(
            BrokerVmSessionPaths::new(&self.broker_material_root(), session_id)
                .staging_dir()
                .join(BROKER_VM_LOG_FILE),
            session_id,
            BROKER_VM_READY_POLL_INTERVAL,
        )
    }

    /// Re-attach a broker-VM log tail (only when `had` — i.e. there was one) after
    /// a failed stop/cleanup, so a still-live session stays observable and
    /// retryable rather than appearing orphaned with forwarding stopped.
    pub(super) async fn reattach_broker_log_forwarder_if(&self, had: bool, session_id: SessionId) {
        if had {
            let forwarder = self.spawn_broker_log_forwarder(session_id);
            self.vm_broker_attached
                .lock()
                .await
                .insert(session_id, forwarder);
        }
    }

    /// Remove the persisted state record for `session_id` on a blocking
    /// thread, releasing its subnet index and per-session names. Nested
    /// result as in [`Self::spawn_cleanup_session`].
    async fn spawn_remove_session_state(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), AgentVmSessionManagerError>, tokio::task::JoinError> {
        let store = self.config.lifecycle.state_store.clone();
        tokio::task::spawn_blocking(move || {
            remove_managed_agent_vm_session_state(&store, session_id)
        })
        .await
    }

    /// Remove this session's per-session broker material dir — copied secrets
    /// included — on a blocking thread. Nested result as in
    /// [`Self::spawn_cleanup_session`].
    ///
    /// MUST run only after teardown has confirmed the broker VM (which mounts
    /// the material read-only) is gone, and MUST precede
    /// [`Self::spawn_remove_session_state`]: a removal failure is surfaced, not
    /// swallowed, so the caller keeps the persisted state record. That record is
    /// the sole reconciliation obligation, so dropping it while the copied
    /// secrets remain would strand them on disk with nothing to drive a retry.
    /// Absence-based (a missing dir is a success), so it is a no-op for host
    /// placement — whose material dir never existed — and idempotent on retry.
    async fn spawn_remove_broker_material(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), BrokerMaterialRemoveError>, tokio::task::JoinError> {
        let session_dir = BrokerVmSessionPaths::new(&self.broker_material_root(), session_id)
            .session_dir()
            .to_path_buf();
        tokio::task::spawn_blocking(move || {
            remove_dir_all_if_present(&session_dir).map_err(|source| BrokerMaterialRemoveError {
                path: session_dir,
                source,
            })
        })
        .await
    }

    async fn stop_session_locked<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        // Classify the session using the state store only (bounded — no container/PF
        // commands): a genuinely absent record (`NotFound`) is an unrelated/ordinary
        // broker session that was never an agent VM and must NOT have its audit row
        // closed here. Any other load error is propagated (fail closed) rather than
        // mis-classified as unmanaged — treating a transient failure as "not an agent
        // VM" could let a later successful teardown remove the record and report a
        // clean stop while the broker was never de-authorised. Done *before* the
        // forwarder is drained so this fallible step, on error, leaves a still-live
        // VM-broker session's log tail attached rather than orphaned.
        let managed = self.agent_vm_session_is_managed(session_id).await?;

        // Drain+stop the broker log tail *before* cleanup — a successful stop
        // removes the per-session material dir that holds the log file (the
        // `spawn_remove_broker_material` step below), so a drain afterwards would
        // find nothing and lose the tail. Remove first so the lock is not held
        // across the drain await.
        let forwarder = self.vm_broker_attached.lock().await.remove(&session_id);
        let had_forwarder = forwarder.is_some();
        if let Some(forwarder) = forwarder {
            forwarder.drain_and_stop().await;
        }

        // For a managed session, revoke broker authority up front — before the
        // *unbounded* infrastructure teardown and independently of it — by closing
        // the audit session (the broker refuses to mint once `closed_at` is set).
        // This is a bounded local write, so even if a container/PF command later
        // hangs the guest is already de-authorised. The in-process broker's graceful
        // HTTP drain is NOT awaited here: `shutdown()` waits on in-flight handlers
        // with no deadline, and an untrusted guest holding a connection could stall
        // its own teardown, so the drain is deferred until after teardown has
        // disconnected the guest.
        let audit_close = if managed {
            state.audit.close_session(session_id, UnixMillis::now())
        } else {
            Ok(())
        };

        if let Err(err) = self.run_cleanup_session(session_id).await {
            // Teardown failed: it leaves the material dir (and log) for the retry, so
            // the guest may still be live. Authority is already revoked (audit
            // closed); the in-process broker is left attached but de-authorised,
            // reported as such and torn down on a later stop / boot reconcile. Retain
            // any co-occurring audit-close failure in the log (as the reconcile path
            // does); the persisted state record is kept for retry.
            if let Err(audit) = &audit_close {
                tracing::warn!(
                    session_id = %session_id,
                    error = %audit,
                    "agent VM stop could not close audit session (teardown also failed)",
                );
            }
            self.reattach_broker_log_forwarder_if(had_forwarder, session_id)
                .await;
            return Err(err);
        }

        // Teardown succeeded, so the guest is gone and this WAS a managed session.
        // Now drain + drop the in-process broker: the drain completes because the
        // guest is disconnected, and the runtime-map lock is released before awaiting
        // `shutdown()` so a slow drain cannot block listing or unrelated sessions.
        let running = self.running.lock().await.remove(&session_id);
        let http_shutdown = match running {
            // Destructured so the concurrency slot's release is visible here
            // rather than implied: it is freed when `_slot` drops at the end of
            // this statement, whatever the shutdown returns.
            Some(RunningAgentVm { session, _slot }) => session.shutdown().await,
            None => Ok(()),
        };

        // If the up-front close failed transiently (e.g. `SQLITE_BUSY` from the live
        // broker VM), teardown has since removed that contender, so retry the
        // idempotent close now rather than failing an otherwise-clean stop on a stale
        // error.
        let audit_close = match audit_close {
            Ok(()) => Ok(()),
            Err(_) => state.audit.close_session(session_id, UnixMillis::now()),
        };

        // Surface any revocation failure before dropping the durable records, so the
        // state record — the sole reconciliation obligation — is kept for retry
        // rather than stranded.
        match (audit_close, http_shutdown) {
            (Ok(()), Ok(())) => {
                // Remove the copied secrets before dropping the state record, so a
                // removal failure keeps the record (and thus the reconciliation
                // obligation) rather than stranding the secrets on disk.
                self.spawn_remove_broker_material(session_id).await??;
                self.spawn_remove_session_state(session_id).await??;
                Ok(())
            }
            (Err(audit), Ok(())) => Err(AgentVmDaemonError::Audit(audit)),
            (Ok(()), Err(http)) => Err(AgentVmDaemonError::HttpShutdown(http)),
            (Err(audit), Err(http)) => Err(AgentVmDaemonError::StopBothFailed {
                audit: Box::new(audit),
                http: Box::new(http),
            }),
        }
    }

    /// Whether `session_id` is a managed agent-VM session, from the state store only
    /// (no container/PF commands — bounded). `Ok(true)` when a state record exists,
    /// `Ok(false)` only when it is genuinely absent (`NotFound` — an ordinary broker
    /// session that was never an agent VM, whose audit row agent-VM stop must not
    /// close). Any other load failure is propagated so a stop fails closed rather
    /// than silently skipping authority revocation.
    pub(super) async fn agent_vm_session_is_managed(
        &self,
        session_id: SessionId,
    ) -> Result<bool, AgentVmDaemonError> {
        let store = self.config.lifecycle.state_store.clone();
        match tokio::task::spawn_blocking(move || store.load(session_id)).await? {
            Ok(_) => Ok(true),
            Err(AgentVmSessionStateError::NotFound { .. }) => Ok(false),
            Err(other) => Err(AgentVmDaemonError::Manager(other.into())),
        }
    }

    async fn release_and_wait_for_workspace_bootstrap(
        &self,
        vm_name: &str,
    ) -> Result<(), AgentVmDaemonError> {
        self.release_and_wait_for_workspace_bootstrap_with_timeout(
            vm_name,
            AGENT_VM_WORKSPACE_BOOTSTRAP_TIMEOUT,
        )
        .await
    }

    /// Signal the guest that the broker is up (so the boot-time egress gate's
    /// positive control + broker-ready wait can proceed), then wait for the
    /// guest's bootstrap sentinels. Used for EVERY session: both guest scripts
    /// run the gate and signal bootstrap-ok/failed identically, so a gate
    /// failure is surfaced here rather than returning a "started" VM the gate
    /// then kills. Released only after the broker has spawned, so it cannot lie.
    pub(super) async fn release_and_wait_for_workspace_bootstrap_with_timeout(
        &self,
        vm_name: &str,
        timeout: Duration,
    ) -> Result<(), AgentVmDaemonError> {
        // The whole release+wait dance shares one budget: `timeout`. Every
        // `container exec` runs under the *remaining* budget so a wedged guest
        // exec cannot outlast it (the elapsed check used to sit only *after*
        // the exec returned, so a hung exec never reached it). The guest is
        // treated as compromised, so this bound is authority-side, not advisory.
        let start = Instant::now();

        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
        }
        self.run_container_exec_shell(
            vm_name,
            "release guest bootstrap",
            &format!(
                "mkdir -p /run/writ-agent-vm && touch {}",
                AGENT_VM_WORKSPACE_BROKER_READY_PATH
            ),
            remaining,
        )
        .await?;

        let mut poll_count = 0;
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
            }
            let output = self
                .run_container_exec_shell(
                    vm_name,
                    "inspect workspace bootstrap",
                    &format!(
                        "if [ -f {ok} ]; then printf ok; \
                         elif [ -f {failed} ]; then printf 'failed\\n'; tail -c {tail} {failed}; \
                         else printf pending; fi",
                        ok = AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH,
                        failed = AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH,
                        tail = AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TAIL_CAPTURE,
                    ),
                    remaining,
                )
                .await?;
            let status = output.stdout.trim();
            if status == "ok" {
                return Ok(());
            }
            if let Some(message) = status.strip_prefix("failed") {
                let message = normalise_workspace_bootstrap_failure_message(message.trim());
                return Err(AgentVmDaemonError::WorkspaceBootstrapFailed {
                    message: if message.is_empty() {
                        "guest did not report a failure message".into()
                    } else {
                        message
                    },
                });
            }
            if start.elapsed() >= timeout {
                return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
            }
            let poll_interval = workspace_bootstrap_poll_interval(poll_count);
            poll_count = poll_count.saturating_add(1);
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Run `sh -c <script>` inside the guest VM via `container exec`, capturing
    /// its output under a byte cap and the whole invocation under `deadline`.
    ///
    /// Both bounds matter because the guest is untrusted: the payload of the
    /// bootstrap inspect is a guest-controlled file, so an unbounded read could
    /// exhaust host memory, and a wedged exec could hang past the caller's
    /// overall timeout. [`ProcessInvocation::run_capturing_output_bounded`] caps
    /// the capture (and kills the child if it floods), and `kill_on_drop` means
    /// the outer `tokio::time::timeout` cancelling the future kills the child
    /// rather than leaking it.
    async fn run_container_exec_shell(
        &self,
        vm_name: &str,
        step: &'static str,
        script: &str,
        deadline: Duration,
    ) -> Result<BoundedOutput, AgentVmDaemonError> {
        let invocation = ProcessInvocation::new(
            self.config.lifecycle.tools.container(),
            ["exec", vm_name, "sh", "-c", script],
        );
        let output = match tokio::time::timeout(
            deadline,
            invocation.run_capturing_output_bounded(AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT),
        )
        .await
        {
            Err(_elapsed) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapExecTimedOut {
                    step,
                    timeout: deadline,
                });
            }
            Ok(Err(ProcessInvocationError::Run { source, .. })) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapSpawn { step, source });
            }
            Ok(Err(other)) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapSpawn {
                    step,
                    source: std::io::Error::other(other.to_string()),
                });
            }
            Ok(Ok(output)) => output,
        };
        if output.truncated {
            return Err(AgentVmDaemonError::WorkspaceBootstrapOutputTooLarge {
                step,
                limit: AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT,
            });
        }
        match output.status {
            Some(status) if status.success() => Ok(output),
            status => Err(AgentVmDaemonError::WorkspaceBootstrapCommandFailed {
                step,
                status: status
                    .and_then(|status| status.code())
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                stderr: output.stderr.trim().to_string(),
            }),
        }
    }

    async fn cleanup_failed_started_session(
        &self,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        // Drain the log tail *before* the material dir holding the log file is
        // removed (the `spawn_remove_broker_material` step below). A fully-started
        // (inserted) session drains here; a start that failed before insertion
        // drained its own local forwarder already, so this is then a no-op.
        let forwarder = self.vm_broker_attached.lock().await.remove(&session_id);
        let had_forwarder = forwarder.is_some();
        if let Some(forwarder) = forwarder {
            forwarder.drain_and_stop().await;
        }

        if let Err(err) = self.run_cleanup_session(session_id).await {
            // Failed teardown leaves the material dir (and log) for the retry, so
            // re-attach a fresh tail to keep a still-live session observable.
            self.reattach_broker_log_forwarder_if(had_forwarder, session_id)
                .await;
            return Err(err);
        }

        if let Some(RunningAgentVm { session, _slot }) =
            self.running.lock().await.remove(&session_id)
        {
            // `_slot` drops here, returning this run's place in the bound even if
            // the shutdown below fails.
            session.shutdown().await?;
        }

        // Remove the copied secrets before dropping the state record: a removal
        // failure keeps the record so the reconciliation obligation survives.
        self.spawn_remove_broker_material(session_id).await??;
        self.spawn_remove_session_state(session_id).await??;
        Ok(())
    }

    /// Treat every persisted session as a cleanup obligation and drive it to
    /// completion: tear down the VM/firewall/network via the persisted facts and
    /// close the audit row (revoking broker authority) — each attempted regardless
    /// of the other's outcome — then remove the per-session material dir (copied
    /// secrets), and finally remove the state record.
    ///
    /// MUST be called before [`crate::server::run_with_agent_vm`] begins
    /// accepting connections. Subnet selection in `start_session` is driven
    /// by `state_store.load_all()`; accepting new starts before reconcile
    /// completes would race the new session against the persisted one that
    /// is about to be freed, either colliding on the subnet index (rejected,
    /// noisy) or — worse — letting the new session win and leaking the old
    /// VM's network.
    ///
    /// Per-session failures are collected into the report; the sweep keeps
    /// going. A failed session keeps its state record so the next boot
    /// retries. `LoadAll` failure aborts before any session is touched and
    /// is surfaced as the outer `Err`.
    pub async fn reconcile_persisted_sessions(
        &self,
        audit: &Arc<AuditLog>,
    ) -> Result<AgentVmReconcileReport, AgentVmReconcileError> {
        let store = self.config.lifecycle.state_store.clone();
        let states = tokio::task::spawn_blocking(move || store.load_all())
            .await?
            .map_err(AgentVmReconcileError::LoadAll)?;

        let mut report = AgentVmReconcileReport::default();
        for state in states {
            let session_id = state.session_id();
            match self.reconcile_one_session(audit, session_id).await {
                Ok(()) => report.cleaned.push(session_id),
                Err((stage, error)) => report.failed.push(AgentVmReconcileFailure {
                    session_id,
                    stage,
                    error,
                }),
            }
        }
        Ok(report)
    }

    async fn reconcile_one_session(
        &self,
        audit: &Arc<AuditLog>,
        session_id: SessionId,
    ) -> Result<(), (AgentVmReconcileStage, AgentVmReconcileStageError)> {
        // Revoke broker authority up front — before the *unbounded* infrastructure
        // teardown, and independently of it. Every persisted session here is a
        // managed agent-VM session; closing its audit row is a bounded local
        // operation that makes the broker refuse to mint (the host broker and any
        // autonomous broker VM both consult `closed_at`), so doing it first means a
        // hung container/PF command in teardown cannot leave a surviving broker VM
        // authorised during boot.
        //
        // The result is captured but not branched on: teardown must still run even
        // when the close failed — skipping it would leave the broker VM running, and
        // under `SQLITE_BUSY` held by that very VM, tearing it down is often what
        // frees the audit-DB lock so a later retry can close. Any failure keeps the
        // state record (we stop before removing it) so the next boot retries, and
        // the daemon refuses to start while an obligation remains.
        let audit_close = audit.close_session(session_id, UnixMillis::now());

        let cleanup = self.spawn_cleanup_session(session_id).await;

        // A teardown failure (a still-live VM) is the more urgent condition, so
        // report it; retain any co-occurring audit-close failure in the log rather
        // than dropping it silently.
        let cleanup_failure = match cleanup {
            Err(join) => Some((AgentVmReconcileStage::Cleanup, join.into())),
            Ok(Err(err)) => Some((AgentVmReconcileStage::Cleanup, err.into())),
            Ok(Ok(())) => None,
        };
        if let Some(failure) = cleanup_failure {
            if let Err(err) = &audit_close {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "agent VM reconcile could not close audit session (teardown also failed)",
                );
            }
            return Err(failure);
        }
        // Teardown succeeded. If the up-front close failed transiently (e.g.
        // `SQLITE_BUSY` from the broker VM that teardown has now removed), retry the
        // idempotent close rather than failing an otherwise-clean reconcile — which
        // would keep the state record and abort daemon startup until another boot.
        if let Err(_stale) = audit_close
            && let Err(err) = audit.close_session(session_id, UnixMillis::now())
        {
            return Err((AgentVmReconcileStage::AuditClose, err.into()));
        }

        // Remove the copied secrets before the state record: a failure here keeps
        // the record so this session is retried on the next boot rather than the
        // secrets being stranded with no reconciliation obligation left.
        match self.spawn_remove_broker_material(session_id).await {
            Err(join) => return Err((AgentVmReconcileStage::MaterialRemove, join.into())),
            Ok(Err(err)) => return Err((AgentVmReconcileStage::MaterialRemove, err.into())),
            Ok(Ok(())) => {}
        }

        match self.spawn_remove_session_state(session_id).await {
            Err(join) => return Err((AgentVmReconcileStage::StateRemove, join.into())),
            Ok(Err(err)) => return Err((AgentVmReconcileStage::StateRemove, err.into())),
            Ok(Ok(())) => {}
        }

        Ok(())
    }

    pub async fn list_sessions(&self) -> Result<Vec<AgentVmSessionInfo>, AgentVmDaemonError> {
        // Listing is observational. Avoid the lifecycle mutex so an operator
        // can inspect persisted cleanup obligations while a start/stop is slow
        // or wedged; the state-store lock and running-runtime mutex provide a
        // bounded snapshot that may be retried.
        let store = self.config.lifecycle.state_store.clone();
        let states = tokio::task::spawn_blocking(move || store.load_all()).await??;
        let running = self.running.lock().await;
        let vm_attached = self.vm_broker_attached.lock().await;
        // A session is runtime-attached if its in-process broker is live (host) or
        // it is a live vm-broker session (no in-process broker, tracked separately).
        let attached = |id: &SessionId| running.contains_key(id) || vm_attached.contains_key(id);
        Ok(states
            .into_iter()
            .map(|state| AgentVmSessionInfo {
                session_id: state.session_id(),
                status: state.status(),
                subnet_index: state.subnet_index(),
                vm_name: state.names().vm().to_string(),
                network_name: state.names().network().to_string(),
                broker_urls: state
                    .broker_urls()
                    .into_iter()
                    .map(|url| url.as_str().to_string())
                    .collect(),
                runtime_attached: attached(&state.session_id()),
                // Health is only meaningful for a runtime-attached session (the
                // monitor publishes it); a detached/persisted-only session is
                // genuinely Unknown here.
                network_health: if attached(&state.session_id()) {
                    self.network_health
                        .lock()
                        .unwrap()
                        .get(&state.session_id())
                        .copied()
                        .unwrap_or(NetworkHealth::Unknown)
                } else {
                    NetworkHealth::Unknown
                },
            })
            .collect())
    }

    /// The guest environment variables shared by both broker placements: the
    /// broker URL and bearer token the agent authenticates with, the nix-cache
    /// proxy and trust config (served by the broker wherever it runs), the
    /// egress-gate IPv6 posture, and the strict pre-warm substituter when set.
    fn build_agent_guest_env(
        &self,
        broker_url: &str,
        bearer_token: &str,
    ) -> Result<Vec<AgentVmGuestEnvVar>, AgentVmDaemonError> {
        let trusted_public_keys = self
            .config
            .vm_http
            .nix_cache()
            .trusted_public_keys()
            .nix_conf_value();
        let mut guest_env = vec![
            AgentVmGuestEnvVar::new(AGENT_VM_BROKER_URL_ENV, broker_url.to_string())?,
            AgentVmGuestEnvVar::new(AGENT_VM_BROKER_TOKEN_ENV, bearer_token.to_string())?,
            AgentVmGuestEnvVar::new(
                AGENT_VM_NIX_CACHE_URL_ENV,
                nix_cache_url_for_broker_url(broker_url),
            )?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_BASIC_LOGIN_ENV, VM_NIX_BASIC_LOGIN)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_NETRC_ENV, AGENT_VM_NIX_NETRC_PATH)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, trusted_public_keys)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_CONF_DIR_ENV, AGENT_VM_NIX_CONF_DIR)?,
        ];
        // Tell the boot-time egress gate whether to enforce no-guest-IPv6.
        // Exhaustive over the mode so a future variant must decide: the dual-stack
        // mode provisions a ULA on purpose, so only the no-guest-IPv6 mode forbids
        // a global-scope address.
        let require_no_ipv6 = match self.config.lifecycle.ipv6_mode {
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => "1",
            Ipv6IsolationMode::DualStackRequired => "0",
        };
        guest_env.push(AgentVmGuestEnvVar::new(
            AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV,
            require_no_ipv6,
        )?);
        // Advertise the strict pre-warm-only substituter exactly when the broker
        // actually serves it: its presence pins the devShell warm to the broker's
        // /v1/nix/prewarm so the warm is provably served offline from the
        // pre-warm + flake-input archives. Both placements now serve it — the host
        // broker directly, the vm broker via the re-pointed nix_prewarm_cache_dir
        // and its read-only mount (see broker_vm::with_prewarm_cache_mount) — so
        // the sole gate is whether the operator configured a pre-warm dir.
        if self.config.vm_http.nix_prewarm_cache_dir().is_some() {
            guest_env.push(AgentVmGuestEnvVar::new(
                AGENT_VM_NIX_PREWARM_URL_ENV,
                nix_prewarm_url_for_broker_url(broker_url),
            )?);
        }
        Ok(guest_env)
    }

    // Eight now, because a VM run's concurrency slot has to travel with the
    // session rather than live in a caller's scope. Splitting the parameter list
    // into a struct would move the same fields behind a name without making any
    // of them optional.
    #[allow(clippy::too_many_arguments)]
    async fn start_session_after_audit_opened<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: Option<AgentKind>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
        agent_runs: Option<VmHttpAgentRunService<S>>,
        // `run_slot` is this run's claim on the concurrency bound, released when
        // the session is torn down. `Some` exactly when `agent_runs` is: a
        // session that is not an agent run does not consume an agent-run slot.
        run_slot: Option<crate::server::AgentRunSlot>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // Broker placement seam (see docs/vmnet-accept-bug-and-broker-vm-plan.md):
        // the host path runs an in-process broker; the vm path runs the broker in a
        // dedicated VM, working around the macOS vmnet accept() defect. The vm arm
        // diverges enough (no in-process broker, broker launched before the agent)
        // that it lives in its own method.
        match self.config.lifecycle.broker_placement {
            BrokerPlacement::Host => {}
            BrokerPlacement::Vm => {
                // The v1 broker VM serves clone + nix-cache + proxies only — no
                // agent-run config/outcome routes. Reject an agent-run session
                // up front rather than start a VM whose guest would 404 fetching
                // its run config and leave RunAgent waiting for an outcome that
                // can never be uploaded.
                if agent_runs.is_some() {
                    return Err(AgentVmDaemonError::AgentRunUnsupportedForVmBroker);
                }
                return self
                    .start_vm_broker_session(
                        state,
                        session_id,
                        agent_kind,
                        workspace,
                        guest_command,
                    )
                    .await;
            }
        }

        // Hold subnet_allocation_lock from `choose_subnet_index` through the
        // `claim_agent_vm_session_subnet` write, so the load+pick+commit
        // window is atomic across concurrent starts. The slow VM boot in
        // `complete_agent_vm_session_start` runs after the lock is released.
        let (prepared, plan, starting, broker_url) = {
            let _subnet_guard = self.subnet_allocation_lock.lock().await;
            let lifecycle = self.config.lifecycle.clone();
            let (subnet_index, network) =
                tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
            let staging_root = self.config.vm_http.git_push_staging_root().to_path_buf();
            let staging_store = {
                let path = staging_root.clone();
                tokio::task::spawn_blocking(move || GitPushStagingStore::open(path))
                    .await?
                    .map_err(|source| AgentVmDaemonError::GitPushStagingOpen {
                        path: staging_root,
                        source,
                    })?
            };
            let git_push = VmHttpGitPushService::new(
                Arc::clone(&state),
                Arc::new(staging_store),
                self.config.vm_http.git_push_body_limits(),
            );
            let prepared = prepare_vm_http_session_with_agent_runs(
                Arc::clone(&state),
                &self.config.vm_http,
                session_id,
                network.ipv4(),
                agent_runs,
                Some(git_push),
            )
            .await?;
            let broker_port = prepared.broker_port();
            let broker_url = format!("http://{}:{}/", network.ipv4_gateway(), broker_port.get());
            let broker_ports = BrokerPorts::new([broker_port])?;
            let guest_env =
                self.build_agent_guest_env(&broker_url, prepared.bearer_token().as_str())?;
            let guest_command = wrap_guest_command(workspace.as_ref(), guest_command)?;
            let plan = self.build_agent_plan(
                session_id,
                subnet_index,
                broker_ports,
                guest_env,
                guest_command,
            )?;
            let store = self.config.lifecycle.state_store.clone();
            let plan_for_claim = plan.clone();
            let starting: AgentVmSessionState = tokio::task::spawn_blocking(move || {
                claim_agent_vm_session_subnet(&store, &plan_for_claim)
            })
            .await??;
            (prepared, plan, starting, broker_url)
        };

        let store = self.config.lifecycle.state_store.clone();
        let plan_for_start = plan.clone();
        tokio::task::spawn_blocking(move || {
            complete_agent_vm_session_start(&store, &plan_for_start, starting)
        })
        .await??;

        let running = prepared.spawn();
        self.running.lock().await.insert(
            session_id,
            RunningAgentVm {
                session: running,
                _slot: run_slot,
            },
        );
        // Start the host-side network-health monitor (idempotent). Lazy here
        // because it needs the audit handle, which arrives with the request.
        self.ensure_network_health_monitor(Arc::clone(&state.audit));
        // Release broker-ready and wait for the guest's bootstrap sentinels for
        // EVERY session: both guest scripts run the egress gate and signal
        // bootstrap-ok/failed, so a gate failure (or workspace-init failure) is
        // surfaced before we report the session started.
        if let Err(mut err) = self
            .release_and_wait_for_workspace_bootstrap(plan.names().vm())
            .await
        {
            self.annotate_workspace_bootstrap_error_with_prewarm_audit(
                state.audit.as_ref(),
                session_id,
                &mut err,
            );
            let bootstrap = err.to_string();
            if let Err(cleanup) = self.cleanup_failed_started_session(session_id).await {
                return Err(AgentVmDaemonError::WorkspaceBootstrapCleanupFailed {
                    bootstrap,
                    cleanup: cleanup.to_string(),
                });
            }
            return Err(err);
        }
        Ok(AgentVmStarted {
            session_id,
            broker_url,
        })
    }

    /// Build the agent VM plan from the daemon's lifecycle config. Shared by both
    /// placements; the vm arm builds it twice (a claim plan with an empty guest
    /// env, then a boot plan with the broker VM's URL once discovered).
    fn build_agent_plan(
        &self,
        session_id: SessionId,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        guest_env: Vec<AgentVmGuestEnvVar>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmSessionPlan, AgentVmDaemonError> {
        Ok(AgentVmSessionPlan::new_with_guest_env(
            session_id,
            self.config.lifecycle.pool,
            subnet_index,
            broker_ports,
            self.config.vm_http.broker_port_range(),
            self.config.lifecycle.ipv6_mode,
            self.config.lifecycle.broker_placement,
            self.config.lifecycle.image.clone(),
            guest_env,
            guest_command,
            self.config.lifecycle.resources,
            self.config.lifecycle.tools.clone(),
        )?)
    }

    /// The `broker_placement = vm` start arm: bring up a dedicated broker VM, point
    /// the agent VM at it, and reap everything on any failure.
    ///
    /// Unlike the host arm there is no in-process broker. The broker VM must come
    /// up first (it creates the shared `--internal` network the agent joins), so
    /// the order is: reserve the subnet (claim, under the lock) → materialise the
    /// broker session material + launch the broker VM (unlocked, slow) → discover
    /// its IP → boot the agent VM with the broker URL + bearer + PF allow target →
    /// promote to Running → release and wait for bootstrap.
    ///
    /// The agent boot uses `start_agent_vm_session` + `mark_running` rather than
    /// `complete_agent_vm_session_start`: the latter removes the claimed record on
    /// a boot failure, but here the record (Vm placement) is exactly what lets one
    /// `cleanup_failed_started_session` reap the agent VM *and* the broker VM and
    /// its material (see the persisted-state teardown). So any failure past the
    /// claim routes through that single rollback.
    async fn start_vm_broker_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: Option<AgentKind>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // vm placement needs an agent_kind (which app the broker mints with) and
        // the host facts writd threads in; missing host facts are a wiring bug.
        let agent_kind = agent_kind.ok_or(AgentVmDaemonError::AgentKindRequiredForVmBroker)?;
        let broker_image = self
            .config
            .lifecycle
            .broker_image()
            .ok_or(AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete(
                "broker_image",
            ))?
            .clone();
        let host_config_json = self
            .config
            .lifecycle
            .host_config_json()
            .ok_or(AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete(
                "host_config_json",
            ))?
            .to_string();
        let (host_audit_db, audit_dir) =
            resolve_broker_audit_paths(self.config.lifecycle.host_audit_db().ok_or(
                AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete("host_audit_db"),
            )?)?;

        // The broker binds a fixed port inside its own VM (each broker VM is a
        // distinct IP, so the same port is reusable across sessions).
        let broker_port = self.config.vm_http.broker_port_range().min();
        let broker_ports = BrokerPorts::new([broker_port])?;
        let guest_command = wrap_guest_command(workspace.as_ref(), guest_command)?;

        // Reserve the subnet atomically (choose + claim under the lock). The
        // persisted record carries no guest env, so the claim plan uses an empty
        // one; the boot plan below carries the real broker URL once discovered.
        let (subnet_index, network) = {
            let _subnet_guard = self.subnet_allocation_lock.lock().await;
            let lifecycle = self.config.lifecycle.clone();
            let (subnet_index, network) =
                tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
            let claim_plan = self.build_agent_plan(
                session_id,
                subnet_index,
                broker_ports.clone(),
                Vec::new(),
                guest_command.clone(),
            )?;
            let store = self.config.lifecycle.state_store.clone();
            tokio::task::spawn_blocking(move || claim_agent_vm_session_subnet(&store, &claim_plan))
                .await??;
            (subnet_index, network)
        };

        // Start tailing the broker VM's mirrored log file *before* launch, so that
        // even a readiness timeout (the broker never publishes `ready`) still
        // forwards the broker's own egress-probe/startup diagnostics to the host.
        // The broker truncates+appends this file on the shared session mount; it
        // need not exist yet (the tailer tolerates absence).
        let broker_log_forwarder = self.spawn_broker_log_forwarder(session_id);

        // Everything past the claim reaps via cleanup_failed_started_session on any
        // error (it tears down the agent VM, the broker VM, the material, and the
        // record — see cleanup_managed_agent_vm_session for vm placement).
        let outcome = self
            .complete_vm_broker_start(
                Arc::clone(&state),
                session_id,
                agent_kind,
                &broker_image,
                &host_config_json,
                &host_audit_db,
                &audit_dir,
                broker_port,
                broker_ports,
                subnet_index,
                network,
                guest_command,
            )
            .await;
        match outcome {
            Ok(broker_url) => {
                // No in-process broker to register, but the session is live; track
                // it (and keep tailing its logs) so list_sessions reports it as
                // attached, not orphaned. The tail is drained+stopped on teardown.
                self.vm_broker_attached
                    .lock()
                    .await
                    .insert(session_id, broker_log_forwarder);
                Ok(AgentVmStarted {
                    session_id,
                    broker_url,
                })
            }
            Err(err) => {
                // Forward whatever the broker VM logged up to now — typically the
                // failure itself — then stop the tail, before the VM is torn down.
                // Done up front so it runs on both the keep-VM and cleanup paths,
                // and log the top-level reason host-side (this path was otherwise
                // silent in the daemon's own logs).
                broker_log_forwarder.drain_and_stop().await;
                tracing::warn!(
                    %session_id,
                    error = %err,
                    "agent VM start failed (broker_placement = vm)",
                );
                // Debug escape hatch: leave the failed session's broker + agent VMs
                // (and its Starting state record) in place so an operator can
                // `container logs writ-broker-vm-<session-id>` and `container exec`
                // into it to diagnose. Stop it manually afterwards with
                // `writ agent-vm stop <session-id>`. Default behaviour (knob unset)
                // reaps everything as usual.
                if std::env::var_os("WRIT_KEEP_FAILED_BROKER_VM").is_some() {
                    tracing::warn!(
                        %session_id,
                        "WRIT_KEEP_FAILED_BROKER_VM set: leaving the failed broker VM \
                         (writ-broker-vm-<session-id>) and its agent VM running for \
                         debugging; stop with `writ agent-vm stop <session-id>`",
                    );
                    return Err(err);
                }
                let failure = err.to_string();
                if let Err(cleanup) = self.cleanup_failed_started_session(session_id).await {
                    return Err(AgentVmDaemonError::WorkspaceBootstrapCleanupFailed {
                        bootstrap: failure,
                        cleanup: cleanup.to_string(),
                    });
                }
                Err(err)
            }
        }
    }

    /// The fallible tail of [`Self::start_vm_broker_session`], after the subnet has
    /// been claimed: materialise + launch the broker VM, boot the agent against it,
    /// and wait for bootstrap. Returns the broker URL on success; any error is
    /// rolled back by the caller via `cleanup_failed_started_session`.
    #[allow(clippy::too_many_arguments)]
    async fn complete_vm_broker_start<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: AgentKind,
        broker_image: &ContainerImage,
        host_config_json: &str,
        host_audit_db: &Path,
        audit_dir: &Path,
        broker_port: BrokerPort,
        broker_ports: BrokerPorts,
        subnet_index: u16,
        network: AgentNetwork,
        guest_command: Vec<String>,
    ) -> Result<String, AgentVmDaemonError> {
        let paths = BrokerVmSessionPaths::new(&self.broker_material_root(), session_id);
        // The broker creates and owns the shared internal network the agent joins;
        // its name is the agent network name (session-id derived).
        let internal_network = AgentVmNames::for_session(session_id).network().to_string();
        let bearer = VmHttpBearerToken::generate();
        let bearer_token = bearer.as_str().to_string();

        // Materialise the broker session material (config, spec, bearer, ephemeral
        // secret store) and the launch plan. Synchronous IO, so off the runtime.
        let request = BrokerVmSessionRequest {
            session_id,
            agent_kind,
            image: broker_image.clone(),
            container_tool: self.config.lifecycle.tools.container().to_path_buf(),
            internal_network: internal_network.clone(),
            agent_subnet: network.ipv4(),
            bind_addr: self.config.vm_http.bind_addr(),
            broker_port,
            resources: self.config.lifecycle.resources,
            host_audit_db: host_audit_db.to_path_buf(),
            staging_dir: paths.staging_dir(),
            secrets_dir: paths.secrets_dir(),
            audit_dir: audit_dir.to_path_buf(),
        };
        let host_config_json = host_config_json.to_string();
        let state_for_secrets = Arc::clone(&state);
        let broker_plan = tokio::task::spawn_blocking(move || {
            materialize_broker_vm_session(
                &request,
                &host_config_json,
                &bearer,
                &state_for_secrets.secrets,
            )
        })
        .await??;

        // Authoritative compartment guard: the broker VM is about to
        // read-write-mount the audit DB's directory. Enforce that it holds only
        // the audit DB and its SQLite sidecars — nothing host-owned the guest
        // could replace and the host would then re-read or execute. This runs
        // after materialisation, so every lazily-written file (per-session broker
        // material, socket, bearer, notes) that could land under a misconfigured
        // audit directory already exists and is seen. Any error rolls back via
        // the caller's `cleanup_failed_started_session`.
        let host_audit_db_for_check = host_audit_db.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::config::ensure_audit_dir_is_dedicated(&host_audit_db_for_check)
        })
        .await??;

        // Launch the broker VM and discover its address on the shared network.
        let broker_ipv4 = launch_broker_vm(
            &broker_plan,
            &paths.staging_dir().join("ready"),
            broker_port,
            BROKER_VM_READY_TIMEOUT,
            BROKER_VM_READY_POLL_INTERVAL,
        )
        .await
        .map_err(|source| AgentVmDaemonError::BrokerVmLaunch { session_id, source })?;
        let broker_url = broker_url(broker_ipv4, broker_port);

        // Boot the agent VM pointed at the broker VM: WRIT_BROKER_URL + token in the
        // guest env, and the host PF allow target set to the broker VM's IP.
        let guest_env = self.build_agent_guest_env(&broker_url, &bearer_token)?;
        let boot_plan = self
            .build_agent_plan(
                session_id,
                subnet_index,
                broker_ports,
                guest_env,
                guest_command,
            )?
            .with_broker_pf_host(broker_ipv4);

        let store = self.config.lifecycle.state_store.clone();
        let boot_plan_for_start = boot_plan.clone();
        // start_agent_vm_session rolls back its own agent infrastructure (VM + PF,
        // not the broker-owned network) on a boot failure; the broker VM is reaped
        // by the caller's cleanup_failed_started_session.
        tokio::task::spawn_blocking(move || start_agent_vm_session(&boot_plan_for_start))
            .await?
            .map_err(AgentVmSessionManagerError::Start)?;
        let store_for_running = store.clone();
        let starting =
            tokio::task::spawn_blocking(move || store_for_running.load(session_id)).await??;
        // Promote to Running while recording the discovered broker VM IP, so
        // list_sessions reports the real broker URL (not the subnet gateway).
        tokio::task::spawn_blocking(move || {
            store.mark_running_with_broker_ipv4(&starting, broker_ipv4)
        })
        .await??;

        self.ensure_network_health_monitor(Arc::clone(&state.audit));
        if let Err(mut err) = self
            .release_and_wait_for_workspace_bootstrap(boot_plan.names().vm())
            .await
        {
            self.annotate_workspace_bootstrap_error_with_prewarm_audit(
                state.audit.as_ref(),
                session_id,
                &mut err,
            );
            return Err(err);
        }
        Ok(broker_url)
    }

    fn annotate_workspace_bootstrap_error_with_prewarm_audit(
        &self,
        audit: &AuditLog,
        session_id: SessionId,
        err: &mut AgentVmDaemonError,
    ) {
        if self.config.vm_http.nix_prewarm_cache_dir().is_none() {
            return;
        }
        if !matches!(err, AgentVmDaemonError::WorkspaceBootstrapFailed { .. }) {
            return;
        }
        let Some(diagnostic) = workspace_bootstrap_prewarm_diagnostic_from_audit(audit, session_id)
        else {
            return;
        };
        if let AgentVmDaemonError::WorkspaceBootstrapFailed { message } = err {
            if !message.is_empty() {
                message.push_str("\n\n");
            }
            message.push_str(&diagnostic);
        }
    }

    #[cfg(test)]
    pub(super) fn choose_subnet_index(&self) -> Result<(u16, AgentNetwork), AgentVmDaemonError> {
        choose_subnet_index(&self.config.lifecycle)
    }
}
