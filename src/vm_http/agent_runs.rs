//! Agent runs: serves the in-VM `/v1/agent-runs/{id}/config` and
//! `/v1/agent-runs/{id}/outcome` endpoints. The config route delivers the
//! one-shot prompt and model to the guest; the outcome route ingests the
//! terminal status, exit code, and stdout/stderr stream summaries, persists
//! the retained bytes to disk, and writes an audit record.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunStreamUpload,
    VM_AGENT_RUN_OUTCOME_PATH_SUFFIX, VM_AGENT_RUN_PATH_PREFIX, VmAgentRunConfigResponse,
    VmAgentRunOutcomeUpload,
};
use crate::audit::{AUDIT_WRITE_FAILURE_TARGET, AgentRunOutcomeAuditRecord};
use crate::core::{SessionId, UnixMillis};
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpResponse, VmHttpStatus};

// The JSON upload cap bounds retained bytes on the wire. This larger cap is a
// defense-in-depth bound on the guest-reported full stream length, which is
// intentionally not trusted for truncated-stream audit rows.
const MAX_AGENT_RUN_STREAM_AUDIT_BYTES: u64 = 1024 * 1024 * 1024;

pub struct VmHttpAgentRunService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    run_configs: Arc<Mutex<HashMap<AgentRunId, AgentRunInflight>>>,
    log_root: PathBuf,
}

impl<S: SecretStore> std::fmt::Debug for VmHttpAgentRunService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmHttpAgentRunService")
            .field("log_root", &self.log_root)
            .finish_non_exhaustive()
    }
}

impl<S: SecretStore> Clone for VmHttpAgentRunService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            run_configs: Arc::clone(&self.run_configs),
            log_root: self.log_root.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct AgentRunInflight {
    prompt: AgentPrompt,
    model: String,
}

impl<S: SecretStore> VmHttpAgentRunService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>, log_root: impl Into<PathBuf>) -> Self {
        Self {
            broker_state,
            run_configs: Arc::new(Mutex::new(HashMap::new())),
            log_root: log_root.into(),
        }
    }

    pub fn insert_run_config(
        &self,
        run_id: AgentRunId,
        prompt: AgentPrompt,
        model: impl Into<String>,
    ) {
        self.run_configs
            .lock()
            .expect("agent run config lock should not be poisoned")
            .insert(
                run_id,
                AgentRunInflight {
                    prompt,
                    model: model.into(),
                },
            );
    }

    fn take_run_config(&self, run_id: AgentRunId) -> Option<AgentRunInflight> {
        self.run_configs
            .lock()
            .expect("agent run config lock should not be poisoned")
            .remove(&run_id)
    }

    fn log_root(&self) -> &Path {
        &self.log_root
    }

    fn broker_state(&self) -> &BrokerState<S> {
        &self.broker_state
    }
}

pub(super) fn parse_agent_run_config_target(target: &str) -> Option<AgentRunId> {
    let suffix = target
        .strip_prefix(VM_AGENT_RUN_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix("/config")?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

pub(super) fn parse_agent_run_outcome_target(target: &str) -> Option<AgentRunId> {
    let suffix = target
        .strip_prefix(VM_AGENT_RUN_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix(&format!("/{VM_AGENT_RUN_OUTCOME_PATH_SUFFIX}"))?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

pub(super) fn route_agent_run_config_request<S: SecretStore>(
    run_id: AgentRunId,
    service: &VmHttpAgentRunService<S>,
) -> VmHttpResponse {
    let Some(inflight) = service.take_run_config(run_id) else {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    };
    VmHttpResponse::json(
        VmHttpStatus::Ok,
        &VmAgentRunConfigResponse::new(run_id, inflight.prompt, inflight.model),
    )
}

pub(super) fn route_agent_run_outcome_request<S: SecretStore>(
    run_id: AgentRunId,
    authenticated_session_id: SessionId,
    body: &[u8],
    service: &VmHttpAgentRunService<S>,
) -> VmHttpResponse {
    let broker_state = service.broker_state();
    // Bind the run to the authenticated session before any lookup or write.
    // The run's owning session is fixed at request time; a session may only
    // submit an outcome for a run it owns. A run belonging to another session —
    // or one that does not exist — is reported identically as "not found", so
    // this endpoint cannot be used as an oracle for other sessions' run IDs.
    match broker_state.audit.get_agent_run(run_id) {
        Ok(Some(record)) if record.session_id == authenticated_session_id => {}
        Ok(_) => return VmHttpResponse::text(VmHttpStatus::NotFound, "not found"),
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "agent_run_lookup",
                run_id = %run_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    }
    match broker_state.audit.get_agent_run_outcome(run_id) {
        Ok(Some(_)) => return VmHttpResponse::text(VmHttpStatus::Ok, "ok"),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "agent_run_outcome_lookup",
                run_id = %run_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    }
    let upload = match serde_json::from_slice::<VmAgentRunOutcomeUpload>(body) {
        Ok(upload) => upload,
        Err(_) => return VmHttpResponse::text(VmHttpStatus::BadRequest, "invalid outcome JSON"),
    };
    if upload.run_id != run_id {
        return VmHttpResponse::text(VmHttpStatus::BadRequest, "outcome run ID mismatch");
    }

    let outcome = match materialize_agent_run_outcome_upload(upload, service.log_root()) {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    if let Err(err) = broker_state
        .audit
        .record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::now(),
            outcome,
        })
    {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "agent_run_outcome",
            run_id = %run_id,
            error = %err,
            "audit write failed",
        );
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    VmHttpResponse::text(VmHttpStatus::Ok, "ok")
}

fn materialize_agent_run_outcome_upload(
    upload: VmAgentRunOutcomeUpload,
    log_root: &Path,
) -> Result<AgentRunOutcome, VmHttpResponse> {
    if !log_root.is_absolute() {
        return Err(VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log root is invalid",
        ));
    }
    let run_dir = log_root.join(upload.run_id.to_string());
    create_private_dir(&run_dir).map_err(|err| {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "agent_run_log_directory",
            run_id = %upload.run_id,
            run_dir = %run_dir.display(),
            error = %err,
            "agent run log directory write failed",
        );
        VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log write failed",
        )
    })?;
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    let stdout = materialize_agent_run_stream(upload.stdout, &stdout_path)?;
    let stderr = materialize_agent_run_stream(upload.stderr, &stderr_path)?;
    Ok(AgentRunOutcome {
        run_id: upload.run_id,
        status: upload.status,
        exit_code: upload.exit_code,
        stdout,
        stderr,
    })
}

fn materialize_agent_run_stream(
    upload: AgentRunStreamUpload,
    path: &Path,
) -> Result<AgentRunStreamSummary, VmHttpResponse> {
    let retained = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&upload.retained_base64)
            .map_err(|_| {
                VmHttpResponse::text(VmHttpStatus::BadRequest, "invalid outcome stream base64")
            })?
    };
    let retained_len = retained.len() as u64;
    if upload.byte_len > MAX_AGENT_RUN_STREAM_AUDIT_BYTES {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream byte count exceeds audit limit",
        ));
    }
    if !is_sha256_hex(&upload.sha256_hex) || !is_sha256_hex(&upload.retained_sha256_hex) {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "invalid outcome stream hash",
        ));
    }
    if crate::agent_run::sha256_hex(&retained) != upload.retained_sha256_hex {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream retained hash mismatch",
        ));
    }
    if retained_len > upload.byte_len {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream retained bytes exceed total byte count",
        ));
    }
    if upload.truncated {
        if retained_len >= upload.byte_len {
            return Err(VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                "truncated outcome stream must have uncaptured bytes",
            ));
        }
    } else if retained_len != upload.byte_len {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "untruncated outcome stream retained bytes must match total byte count",
        ));
    } else if crate::agent_run::sha256_hex(&retained) != upload.sha256_hex {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "untruncated outcome stream hash mismatch",
        ));
    }

    let (audited_byte_len, audited_sha256_hex) = if upload.truncated {
        (retained_len, upload.retained_sha256_hex)
    } else {
        (upload.byte_len, upload.sha256_hex)
    };

    write_private_file(path, &retained).map_err(|err| {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "agent_run_log_stream",
            path = %path.display(),
            error = %err,
            "agent run log stream write failed",
        );
        VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log write failed",
        )
    })?;
    Ok(AgentRunStreamSummary {
        path: path.to_path_buf(),
        byte_len: audited_byte_len,
        sha256_hex: audited_sha256_hex,
        truncated: upload.truncated,
    })
}

fn is_sha256_hex(raw: &str) -> bool {
    // Lowercase-only: agent_run::sha256_hex emits lowercase, and the
    // downstream byte-string comparison is case-sensitive. Accepting
    // uppercase here would only let it fail later with a misleading hash
    // mismatch error.
    raw.len() == 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

fn write_private_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(path)?;
            if existing == body {
                return Ok(());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists with different contents", path.display()),
            ));
        }
        Err(err) => return Err(err),
    };
    use std::io::Write as _;
    file.write_all(body)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use base64::Engine as _;
    use wiremock::MockServer;

    use super::super::tests::{make_broker_state, open_audit_session, session_for_subnet};
    use super::*;
    use crate::core::{Ipv4Cidr, UnixMillis};

    #[tokio::test]
    async fn agent_run_config_route_returns_prompt_and_model_once() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let temp = tempfile::tempdir().unwrap();
        let service = VmHttpAgentRunService::new(state, temp.path().join("agent-runs"));
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000401".parse().unwrap();
        let prompt = AgentPrompt::new("SECRET prompt");
        service.insert_run_config(run_id, prompt.clone(), "gpt-5.4-mini");

        let response = route_agent_run_config_request(run_id, &service);

        assert_eq!(response.status, VmHttpStatus::Ok);
        let body: VmAgentRunConfigResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.run_id(), run_id);
        assert_eq!(body.prompt(), &prompt);
        assert_eq!(body.model(), "gpt-5.4-mini");
        let debug = format!("{body:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");

        let second = route_agent_run_config_request(run_id, &service);
        assert_eq!(second.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn agent_run_outcome_route_records_audit_and_materializes_retained_streams() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000402".parse().unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: None,
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: 6,
                sha256_hex: crate::agent_run::sha256_hex(b"Hello\n"),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"Hello\n"),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"Hello\n"),
            },
            stderr: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
            },
        };
        let body = serde_json::to_vec(&upload).unwrap();
        let prewritten =
            materialize_agent_run_outcome_upload(upload.clone(), service.log_root()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&prewritten.stdout.path).unwrap(),
            "Hello\n"
        );

        let response =
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service);

        assert_eq!(response.status, VmHttpStatus::Ok);
        let outcome = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(
            outcome.outcome.status,
            crate::agent_run::AgentRunTerminalStatus::Succeeded
        );
        assert_eq!(
            std::fs::read_to_string(&outcome.outcome.stdout.path).unwrap(),
            "Hello\n"
        );
        assert!(outcome.outcome.stdout.path.starts_with(temp.path()));

        let retried =
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service);
        assert_eq!(retried.status, VmHttpStatus::Ok);

        // Stage-0 audit-pair oracle (writ-audit::effect_audit_oracle): the run's
        // request row (seeded at launch) and the outcome row recorded by the
        // handler form a complete pair, joined on run_id.
        state
            .audit
            .assert_effect_audit_pairs_complete("agent_run", "agent_run_outcome", "run_id");
    }

    #[tokio::test]
    async fn agent_run_outcome_rejects_a_foreign_session() {
        // A run recorded against session B must not accept an outcome submitted
        // by session A, even if A authenticated and knows B's run ID. Otherwise
        // A could have its output signed under B's prompt, capabilities, and
        // session identity.
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let owner = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, owner.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000404".parse().unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id: owner.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: None,
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: 6,
                sha256_hex: crate::agent_run::sha256_hex(b"Attack"),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"Attack"),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"Attack"),
            },
            stderr: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
            },
        };
        let body = serde_json::to_vec(&upload).unwrap();

        let attacker_session_id = SessionId::new();
        assert_ne!(attacker_session_id, owner.session_id());
        let response =
            route_agent_run_outcome_request(run_id, attacker_session_id, &body, &service);

        assert_eq!(response.status, VmHttpStatus::NotFound);
        // No outcome may have been written for the owner's run.
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_none());

        // The rightful owner can still submit its own outcome afterwards.
        let owner_response =
            route_agent_run_outcome_request(run_id, owner.session_id(), &body, &service);
        assert_eq!(owner_response.status, VmHttpStatus::Ok);
    }

    #[tokio::test]
    async fn agent_run_outcome_rejects_unknown_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000405".parse().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
            },
            stderr: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
            },
        };
        let body = serde_json::to_vec(&upload).unwrap();

        let response =
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service);

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn agent_run_outcome_rejects_unbounded_or_mismatched_truncated_streams() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000403".parse().unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: None,
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));
        let valid_stderr = AgentRunStreamUpload {
            byte_len: 0,
            sha256_hex: crate::agent_run::sha256_hex(b""),
            truncated: false,
            retained_sha256_hex: crate::agent_run::sha256_hex(b""),
            retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
        };
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: u64::MAX,
                sha256_hex: crate::agent_run::sha256_hex(b"untrusted full stream"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"H"),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
            },
            stderr: valid_stderr.clone(),
        };

        let response = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &service,
        );

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let upload = VmAgentRunOutcomeUpload {
            stdout: AgentRunStreamUpload {
                byte_len: 2,
                sha256_hex: crate::agent_run::sha256_hex(b"Hi"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"not-H"),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
            },
            stderr: valid_stderr.clone(),
            ..upload
        };
        let response = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &service,
        );
        assert_eq!(response.status, VmHttpStatus::BadRequest);

        let upload = VmAgentRunOutcomeUpload {
            stdout: AgentRunStreamUpload {
                byte_len: 2,
                sha256_hex: crate::agent_run::sha256_hex(b"unverified full stream"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"H"),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
            },
            stderr: valid_stderr,
            ..upload
        };
        let response = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &service,
        );
        assert_eq!(response.status, VmHttpStatus::Ok);
        let outcome = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(outcome.outcome.stdout.byte_len, 1);
        assert_eq!(
            outcome.outcome.stdout.sha256_hex,
            crate::agent_run::sha256_hex(b"H")
        );
    }
}
