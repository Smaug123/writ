//! Broker-VM launch/teardown planning.
//!
//! [`BrokerVmPlan`](super::BrokerVmPlan) turns the host-side facts about a
//! session (paths, networks, container tool, mounts) into the ordered
//! `ProcessInvocation`s that create the broker VM's networks, launch it, and
//! inspect/stop it. This module holds only that construction logic (an inherent
//! `impl` block); the struct and the types it references stay in the parent
//! module. Split out of `broker_vm.rs` to keep that file readable; behaviour is
//! unchanged.

use super::*;

impl BrokerVmPlan {
    /// Build the plan from the host-side facts. `staging_dir`, `secret_store_dir`
    /// and `audit_dir` are *host* paths the executor has materialised; they are
    /// mounted at the well-known guest targets above.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        image: ContainerImage,
        internal_network: impl Into<String>,
        internal_cidr: Ipv4Cidr,
        resources: AgentVmResources,
        container_tool: impl Into<PathBuf>,
        staging_dir: impl Into<PathBuf>,
        secret_store_dir: impl Into<PathBuf>,
        audit_dir: impl Into<PathBuf>,
    ) -> Self {
        let mounts = vec![
            BrokerVmMount {
                source: staging_dir.into(),
                target: BROKER_VM_SESSION_DIR.to_string(),
                readonly: false,
            },
            BrokerVmMount {
                source: secret_store_dir.into(),
                target: BROKER_VM_SECRETS_DIR.to_string(),
                readonly: true,
            },
            BrokerVmMount {
                source: audit_dir.into(),
                target: BROKER_VM_AUDIT_DIR.to_string(),
                readonly: false,
            },
        ];
        Self {
            names: BrokerVmNames::for_session(session_id),
            image,
            internal_network: internal_network.into(),
            internal_cidr,
            resources,
            container_tool: container_tool.into(),
            mounts,
        }
    }

    /// Bind-mount the host's pre-warm cache dir read-only at
    /// [`BROKER_VM_PREWARM_DIR`], so the in-VM broker serves the pre-warmed
    /// devShell closure local-first (both `/v1/nix/cache` and the strict
    /// `/v1/nix/prewarm` views). A no-op given `None`.
    ///
    /// This is a pure data-plan builder: it mounts whatever path it is given and
    /// does no filesystem check. The caller (`materialize_broker_vm_session_inner`)
    /// owns the effectful decision — it passes `Some` only for a dir that exists,
    /// since virtiofs would fail `container run` on a missing source and a
    /// configured-but-absent pre-warm dir is a tolerated state. [`broker_config_json`]
    /// re-points `nix_prewarm_cache_dir` at this same guest target when the host
    /// set it; if the dir is absent the mount is skipped and the broker serves an
    /// empty pre-warm cache (`NotFound` tolerated), matching host placement.
    #[must_use]
    pub fn with_prewarm_cache_mount(mut self, host_prewarm_dir: Option<PathBuf>) -> Self {
        if let Some(source) = host_prewarm_dir {
            self.mounts.push(BrokerVmMount {
                source,
                target: BROKER_VM_PREWARM_DIR.to_string(),
                readonly: true,
            });
        }
        self
    }

    pub fn names(&self) -> &BrokerVmNames {
        &self.names
    }

    /// The `writd broker` argument vector. **Frozen** to the three bootstrap
    /// paths needed to locate and authenticate the session spec; everything else
    /// the broker uses (its ready-file target, its log sink) is carried *in* the
    /// spec (see [`broker_guest_ready_file`] / [`broker_guest_log_file`]), so a
    /// future host→broker parameter can never clap-crash a stale broker image the
    /// way `--log-file` did in #251. See
    /// `docs/plans/2026-07-02-broker-params-into-session-spec.md`.
    fn broker_command(&self) -> Vec<String> {
        vec![
            "writd".to_string(),
            "broker".to_string(),
            "--config".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{CONFIG_FILE}"),
            "--session-spec".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{SESSION_SPEC_FILE}"),
            "--bearer-token-file".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{BEARER_TOKEN_FILE}"),
        ]
    }

    /// `container network create --internal --subnet <cidr> <shared-net>` — the
    /// **shared** internal network the broker and agent both attach to. The
    /// broker arm owns it: it starts first (so it must create the network the
    /// agent later joins) and removes it on teardown. No NAT (`--internal`), so
    /// the agent has no egress by topology.
    pub fn create_internal_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                "--internal".to_string(),
                "--subnet".to_string(),
                self.internal_cidr.to_string(),
                self.internal_network.clone(),
            ],
        )
    }

    /// `container network create <egress>` — no `--internal`, so the broker VM
    /// gets NAT egress on this interface. No `--subnet`: the address space is
    /// irrelevant (nothing else attaches), so let `container` assign one.
    pub fn create_egress_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                self.names.egress_network.clone(),
            ],
        )
    }

    /// `container run …` for the broker VM: dual-homed (egress + internal),
    /// secrets/audit/session bind-mounted, running `writd broker` behind the
    /// route-fix prologue.
    ///
    /// The egress network is attached **first**: Apple `container` puts the
    /// default route on the first-attached network, so this keeps the broker's
    /// outbound traffic on the NAT interface rather than the no-egress internal
    /// one (the prologue then demotes any stray internal default as backup).
    pub fn run_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            "run".to_string(),
            "--name".to_string(),
            self.names.vm.clone(),
            "--network".to_string(),
            self.names.egress_network.clone(),
            "--network".to_string(),
            self.internal_network.clone(),
            "--cpus".to_string(),
            self.resources.cpus().to_string(),
            "--memory".to_string(),
            format!("{}m", self.resources.memory_mib()),
        ];
        for mount in BROKER_VM_TMPFS_MOUNTS {
            args.extend(["--tmpfs".to_string(), (*mount).to_string()]);
        }
        for mount in &self.mounts {
            args.extend(["--mount".to_string(), mount.to_mount_arg()]);
        }
        args.push("-d".to_string());
        args.push(self.image.as_str().to_string());
        // Wrap the broker command in the route-fix prologue (egress default
        // route), passing the internal subnet so it can identify that interface.
        args.extend([
            "sh".to_string(),
            "-c".to_string(),
            BROKER_VM_ROUTE_FIX_SCRIPT.to_string(),
            "writ-broker-route-fix".to_string(),
            self.internal_cidr.to_string(),
        ]);
        args.extend(self.broker_command());
        ProcessInvocation::new(self.container_tool.clone(), args)
    }

    /// `container inspect <broker vm>` — its JSON carries the broker's address on
    /// the internal network once running (see [`parse_broker_ipv4_on_network`])
    /// and its lifecycle state (see [`parse_broker_state`]).
    pub fn inspect_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            ["inspect".to_string(), self.names.vm.clone()],
        )
    }

    /// `container logs -n <tail> <broker vm>` — the last `BROKER_LOG_TAIL_LINES`
    /// lines of the broker process's output, used to salvage the crash reason when
    /// the VM exits before publishing readiness (e.g. a stale image rejecting a
    /// broker CLI flag at argument parsing). The `-n` tail bounds what the host
    /// buffers, so a broker that emitted a large log before crashing cannot force
    /// an unbounded host allocation.
    pub fn logs_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            [
                "logs".to_string(),
                "-n".to_string(),
                BROKER_LOG_TAIL_LINES.to_string(),
                self.names.vm.clone(),
            ],
        )
    }

    /// The shared internal network this broker attaches to; used to pick the
    /// right attachment out of `container inspect` output.
    pub fn internal_network(&self) -> &str {
        &self.internal_network
    }

    /// Idempotent teardown: force-remove the broker VM, then remove its egress
    /// network, then the **shared internal network** the broker arm created.
    ///
    /// The internal network is removed last and must run only after the *agent*
    /// VM has already been stopped (the daemon's vm-arm orchestration stops the
    /// agent VM before tearing the broker down) — otherwise the network is still
    /// in use. The agent VM's own stop plan removes the agent VM only.
    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        broker_vm_removal_invocations(&self.container_tool, &self.names, &self.internal_network)
    }
}
