//! Session-plan construction for the agent-VM lifecycle.
//!
//! [`AgentVmSessionPlan`](super::AgentVmSessionPlan) is the planner: from a
//! session's identity, network, and tool paths it derives the ordered
//! start-step state machine, the individual [`super::ProcessInvocation`]s for
//! network/firewall/VM setup, and the matching teardown plan. This module holds
//! only that construction logic (an inherent `impl` block); the `AgentVmSessionPlan`
//! struct and the types it references stay in the parent module. Extracted from
//! `agent_vm_lifecycle.rs` to keep that file readable; behaviour is unchanged.

use super::*;

impl AgentVmSessionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
        ipv6_mode: Ipv6IsolationMode,
        image: ContainerImage,
        guest_command: Vec<String>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        // The convenience constructor (no guest env) is host-mode only; the vm
        // arm always supplies guest env via `new_with_guest_env`.
        Self::new_with_guest_env(
            session_id,
            pool,
            subnet_index,
            broker_ports,
            broker_port_range,
            ipv6_mode,
            BrokerPlacement::Host,
            image,
            Vec::new(),
            guest_command,
            resources,
            tools,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_guest_env(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
        ipv6_mode: Ipv6IsolationMode,
        broker_placement: BrokerPlacement,
        image: ContainerImage,
        guest_env: Vec<AgentVmGuestEnvVar>,
        guest_command: Vec<String>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        if ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 && guest_command.is_empty() {
            return Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6);
        }
        let (network, names) = derive_session_network(session_id, pool, subnet_index)?;
        Ok(Self {
            session_id,
            pool,
            subnet_index,
            network,
            names,
            broker_ports,
            broker_port_range,
            ipv6_mode,
            broker_placement,
            broker_pf_host: None,
            image,
            guest_env,
            guest_command,
            resources,
            tools,
            owner_token: AgentVmOwnerToken::generate(),
        })
    }

    /// Set the host-PF allow target to the broker VM's IP (vm placement). Without
    /// this the PF allows the subnet gateway (the host-broker default).
    pub fn with_broker_pf_host(mut self, broker_pf_host: Ipv4Addr) -> Self {
        self.broker_pf_host = Some(broker_pf_host);
        self
    }

    /// Pin the ownership token instead of the random default — for tests that
    /// assert the exact `--label` on the create/run invocations.
    pub fn with_owner_token(mut self, owner_token: AgentVmOwnerToken) -> Self {
        self.owner_token = owner_token;
        self
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn network(&self) -> AgentNetwork {
        self.network
    }

    pub fn subnet_index(&self) -> u16 {
        self.subnet_index
    }

    pub fn ipv6_mode(&self) -> Ipv6IsolationMode {
        self.ipv6_mode
    }

    pub fn names(&self) -> &AgentVmNames {
        &self.names
    }

    pub fn broker_urls(&self) -> Vec<BrokerUrl> {
        self.broker_ports
            .as_slice()
            .iter()
            .map(|port| {
                BrokerUrl(format!(
                    "http://{}:{}/",
                    self.network.ipv4_gateway(),
                    port.get()
                ))
            })
            .collect()
    }

    /// Describes the start sequence as a vector of steps. When guest
    /// environment variables are configured, the VM-start step's
    /// [`AgentVmStartInvocation`] is the
    /// [`AgentVmStartInvocation::RuntimeGuestEnvFile`] form;
    /// [`start_agent_vm_session`] writes the real 0600 env file immediately
    /// before invoking `container run`.
    pub fn start_steps(&self) -> Vec<AgentVmStartStep> {
        let mut steps = Vec::new();
        // Host mode creates the agent's own network; the vm arm shares a network
        // the broker arm has already created (and removes), so the agent start
        // skips CreateNetwork. Everything else — inspect/validate and **host PF**
        // — still runs: `--internal` blocks internet egress but NOT host
        // reachability (the macOS gateway 192.168.x.1 is still on the link), so
        // the agent VM must be PF-filtered from host services exactly as in host
        // mode.
        if self.broker_placement == BrokerPlacement::Host {
            // Prove the network is absent before creating it, so a failure never
            // tears down a network this call did not create (the name is
            // host-global but ownership is only per-state-dir). Vm placement joins
            // a broker-owned network and so has no create — and no probe.
            steps.push(AgentVmStartStep::ProbeNetworkAbsent(
                self.stop_plan().network_presence_probe(),
            ));
            steps.push(AgentVmStartStep::CreateNetwork(
                self.create_network_invocation(),
            ));
        }
        steps.push(AgentVmStartStep::InspectAndValidateNetwork(
            self.inspect_network_invocation(),
        ));
        steps.push(AgentVmStartStep::InstallFirewall(
            self.install_firewall_invocation(),
        ));
        // Prove the agent VM is absent before starting it, so a start failure
        // never tears down a VM this call did not create. Both placements create
        // the agent VM, so both probe for it.
        steps.push(AgentVmStartStep::ProbeVmAbsent(
            self.stop_plan().vm_presence_probe(),
        ));
        steps.push(AgentVmStartStep::StartVm(self.start_vm_invocation()));
        if self.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
            // Host-side backstop first: the VM's bridge now exists, so re-load the
            // session PF anchor with an interface-scoped IPv6 deny on it — a
            // guest-tamper-proof block that a root agent cannot undo by re-enabling
            // IPv6 and re-acquiring a vmnet-RA ULA. The pf-helper discovers the
            // interfaces itself from the session gateway. This runs before the
            // in-guest enforce/probe (a defence-in-depth belt) and the release, so
            // IPv6 egress is blocked at the host the whole time.
            steps.push(AgentVmStartStep::InstallGuestIpv6Deny(
                self.firewall_install_invocation(true),
            ));
            // Enforce-then-verify the no-guest-IPv6 posture in one guest exec
            // (the script disables IPv6 in the guest kernel before reporting;
            // see GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT), then release the guest
            // command only once the posture is confirmed.
            steps.push(AgentVmStartStep::ProbeAndValidateGuestIpv6 {
                probe_invocation: self.enforce_and_probe_guest_ipv6_invocation(),
            });
            steps.push(AgentVmStartStep::ReleaseGuestCommand(
                self.release_guest_command_invocation(),
            ));
        }
        steps
    }

    pub fn start_invocations(&self) -> Vec<AgentVmStartInvocation> {
        self.start_steps()
            .into_iter()
            .map(AgentVmStartStep::into_display_invocation)
            .collect()
    }

    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        self.stop_plan().stop_invocations()
    }

    pub fn cleanup_after_partial_start(
        &self,
        completed: CompletedStartStep,
    ) -> Vec<ProcessInvocation> {
        let stop = self.stop_plan();
        match completed {
            // Host removes the network it created. In vm mode the broker arm owns
            // the shared network and no firewall is installed in this phase yet,
            // so there is nothing for the agent to clean up.
            CompletedStartStep::NetworkCreated => match self.broker_placement {
                BrokerPlacement::Host => stop.network_removal_invocations(),
                BrokerPlacement::Vm => Vec::new(),
            },
            // Firewall installed but no VM yet: remove the host PF anchor, and
            // (host only) the network. No VM teardown — `StartVm` has not run.
            // Both placements keep the PF removal — `--internal` does not isolate
            // the agent from host services.
            CompletedStartStep::FirewallInstalled => {
                let mut invocations = vec![stop.remove_firewall_invocation()];
                if self.broker_placement == BrokerPlacement::Host {
                    invocations.extend(stop.network_removal_invocations());
                }
                invocations
            }
            // `stop_invocations` is placement-aware: host removes the VM, host PF,
            // and the network; vm removes the VM and host PF only (the broker arm
            // owns the network).
            CompletedStartStep::VmStarted => stop.stop_invocations(),
        }
    }

    pub fn cleanup_after_start_outcome(&self, outcome: StartOutcome) -> Vec<ProcessInvocation> {
        match cleanup_step_after_start_outcome(outcome) {
            Some(step) => self.cleanup_after_partial_start(step),
            None => Vec::new(),
        }
    }

    pub fn stop_plan(&self) -> AgentVmSessionStopPlan {
        AgentVmSessionStopPlan {
            session_id: self.session_id,
            pool: self.pool,
            network: self.network,
            firewall_ipv6: self.firewall_ipv6_cidr(),
            names: self.names.clone(),
            broker_placement: self.broker_placement,
            tools: self.tools.clone(),
        }
    }

    fn firewall_ipv6_cidr(&self) -> Option<Ipv6Cidr> {
        firewall_ipv6_cidr_for_mode(self.ipv6_mode, self.network)
    }

    fn create_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                "--internal".to_string(),
                "--label".to_string(),
                self.owner_label_arg(),
                "--subnet".to_string(),
                self.network.ipv4().to_string(),
                self.names.network.clone(),
            ],
        )
    }

    /// `writ.owner=<token>`, the ownership label stamped on the network and VM.
    fn owner_label_arg(&self) -> String {
        format!("{AGENT_VM_OWNER_LABEL}={}", self.owner_token.as_str())
    }

    fn inspect_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "network".to_string(),
                "inspect".to_string(),
                self.names.network.clone(),
            ],
        )
    }

    pub fn validate_network_inspection(
        &self,
        inspection: &AppleNetworkInspection,
    ) -> Result<(), NetworkInspectionError> {
        if inspection.ipv4_subnet != self.network.ipv4() {
            return Err(NetworkInspectionError::Ipv4SubnetMismatch {
                expected: self.network.ipv4(),
                actual: inspection.ipv4_subnet,
            });
        }
        if inspection.ipv4_gateway != self.network.ipv4_gateway() {
            return Err(NetworkInspectionError::Ipv4GatewayMismatch {
                expected: self.network.ipv4_gateway(),
                actual: inspection.ipv4_gateway,
            });
        }
        match self.ipv6_mode {
            Ipv6IsolationMode::DualStackRequired => {
                self.validate_dual_stack_ipv6_inspection(inspection)?;
            }
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => {
                validate_ipv4_only_observed_ipv6(inspection)?;
            }
        }
        Ok(())
    }

    fn validate_dual_stack_ipv6_inspection(
        &self,
        inspection: &AppleNetworkInspection,
    ) -> Result<(), NetworkInspectionError> {
        let expected_ipv6 = self.network.ipv6();
        match (inspection.ipv6_subnet, inspection.ipv6_gateway) {
            (Some(ipv6_subnet), Some(ipv6_gateway)) => {
                if ipv6_subnet != expected_ipv6 {
                    return Err(NetworkInspectionError::Ipv6SubnetMismatch {
                        expected: expected_ipv6,
                        actual: ipv6_subnet,
                    });
                }
                let expected_gateway = Ipv6Addr::from(u128::from(expected_ipv6.network()) + 1);
                if ipv6_gateway != expected_gateway {
                    return Err(NetworkInspectionError::Ipv6GatewayMismatch {
                        expected: expected_gateway,
                        actual: ipv6_gateway,
                    });
                }
                Ok(())
            }
            (Some(_), None) => Err(NetworkInspectionError::MissingField("ipv6Gateway")),
            (None, Some(_)) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
            (None, None) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
        }
    }

    fn install_firewall_invocation(&self) -> ProcessInvocation {
        self.firewall_install_invocation(false)
    }

    /// The pf-helper install invocation. `deny_guest_ipv6` selects the post-start
    /// re-install (`Ipv4OnlyNoGuestIpv6`) that adds `--deny-guest-ipv6`: the
    /// pf-helper then discovers the agent's bridge itself (from a fixed root-owned
    /// `ifconfig`) and installs an interface-scoped IPv6 deny. The runner passes no
    /// interface names and no tool path — the privileged boundary owns discovery.
    /// The pre-start install passes `false` (the bridge does not exist yet).
    /// Re-loading the same anchor replaces its rules atomically, so the second
    /// install renders v4 rules + the v6 deny.
    fn firewall_install_invocation(&self, deny_guest_ipv6: bool) -> ProcessInvocation {
        let mut args = vec![
            self.tools.pf_helper.as_os_str().to_os_string(),
            OsString::from("install"),
            OsString::from("--session-id"),
            OsString::from(self.session_id.to_string()),
            OsString::from("--ipv4-pool"),
            OsString::from(self.pool.ipv4_base().to_string()),
            OsString::from("--ipv6-pool"),
            OsString::from(self.pool.ipv6_base().to_string()),
            OsString::from("--ipv4-cidr"),
            OsString::from(self.network.ipv4().to_string()),
        ];
        if self.ipv6_mode == Ipv6IsolationMode::DualStackRequired {
            args.push(OsString::from("--ipv6-cidr"));
            args.push(OsString::from(self.network.ipv6().to_string()));
        }
        // Retarget the PF allow rule to the broker VM (vm placement). Absent for
        // host placement, where the helper defaults to the subnet gateway.
        if let Some(broker_pf_host) = self.broker_pf_host {
            args.push(OsString::from("--broker-host"));
            args.push(OsString::from(broker_pf_host.to_string()));
        }
        for port in self.broker_ports.as_slice() {
            args.push(OsString::from("--broker-port"));
            args.push(OsString::from(port.get().to_string()));
        }
        args.extend([
            OsString::from("--broker-port-min"),
            OsString::from(self.broker_port_range.min().get().to_string()),
            OsString::from("--broker-port-max"),
            OsString::from(self.broker_port_range.max().get().to_string()),
        ]);
        if deny_guest_ipv6 {
            args.push(OsString::from("--deny-guest-ipv6"));
        }
        ProcessInvocation::new(self.tools.sudo.clone(), args)
    }

    fn start_vm_invocation(&self) -> AgentVmStartInvocation {
        let invocation = self.start_vm_invocation_with_env_file(None);
        if self.guest_env.is_empty() {
            AgentVmStartInvocation::Static(invocation)
        } else {
            AgentVmStartInvocation::RuntimeGuestEnvFile {
                invocation,
                display_shell: self
                    .start_vm_invocation_with_env_file(Some(Path::new(GUEST_ENV_FILE_DISPLAY)))
                    .display_shell(),
            }
        }
    }

    fn start_vm_invocation_with_env_file(&self, env_file: Option<&Path>) -> ProcessInvocation {
        let mut args = vec![
            "run".to_string(),
            "--name".to_string(),
            self.names.vm.clone(),
            "--label".to_string(),
            self.owner_label_arg(),
            "--network".to_string(),
            self.names.network.clone(),
            "--cpus".to_string(),
            self.resources.cpus.to_string(),
            "--memory".to_string(),
            format!("{}m", self.resources.memory_mib),
            "-d".to_string(),
        ];
        for mount in AGENT_VM_TMPFS_MOUNTS {
            args.extend(["--tmpfs".to_string(), (*mount).to_string()]);
        }
        if let Some(env_file) = env_file {
            args.extend(["--env-file".to_string(), env_file.display().to_string()]);
        }
        args.push(self.image.as_str().to_string());
        if self.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
            args.extend([
                "sh".to_string(),
                "-c".to_string(),
                IPV4_ONLY_PRELAUNCH_SCRIPT.to_string(),
                "writ-agent-vm-prelaunch".to_string(),
            ]);
        }
        args.extend(self.guest_command.iter().cloned());
        ProcessInvocation::new(self.tools.container.clone(), args)
    }

    pub(super) fn run_start_vm_invocation(&self) -> Result<(), StartFailure> {
        if self.guest_env.is_empty() {
            return self
                .start_vm_invocation_with_env_file(None)
                .run()
                .map_err(StartFailure::from);
        }
        let env_file = TempGuestEnvFile::create(&self.guest_env)?;
        // This relies on Apple Container consuming --env-file before
        // `container run -d` returns; the host-side temp file is deleted as soon
        // as the run command has accepted it.
        self.start_vm_invocation_with_env_file(Some(env_file.path()))
            .run()
            .map_err(StartFailure::from)
    }

    fn enforce_and_probe_guest_ipv6_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "exec".to_string(),
                self.names.vm.clone(),
                "sh".to_string(),
                "-c".to_string(),
                GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.to_string(),
            ],
        )
    }

    fn release_guest_command_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "exec".to_string(),
                self.names.vm.clone(),
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p /run/writ-agent-vm && touch /run/writ-agent-vm/start".to_string(),
            ],
        )
    }
}
