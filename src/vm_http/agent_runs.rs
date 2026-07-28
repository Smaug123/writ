//! Agent runs: serves the in-VM `/v1/agent-runs/{id}/config` and
//! `/v1/agent-runs/{id}/outcome` endpoints. The config route delivers the
//! one-shot prompt and model to the guest; the outcome route ingests the
//! terminal status, exit code, and stdout/stderr stream summaries, persists
//! the retained bytes to disk, and records the run's audit outcome.
//!
//! The outcome route is the *outcome-only* effect shape: the run's `agent_run`
//! request row was minted when the run was **launched**, so this endpoint
//! [resumes](crate::audit::AuditLog::resume_effect) that row through the
//! `broker_effect` driver rather than beginning a second one. Resuming also
//! claims the run id, so two concurrent uploads for one run cannot both write
//! logs and then race for the outcome row's primary key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamCapture, AgentRunStreamSummary,
    AgentRunStreamUpload, VM_AGENT_RUN_OUTCOME_PATH_SUFFIX, VM_AGENT_RUN_PATH_PREFIX,
    VmAgentRunConfigResponse, VmAgentRunOutcomeUpload,
};
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AgentRunAuditRecord, AgentRunAuditTable,
    AgentRunOutcomeAuditRecord, AuditLog, RecordedRequest, ResumeEffectError,
};
use crate::core::{SessionId, UnixMillis};
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::broker_effect::{AcquireFailure, BrokeredEffect, EffectCompletion, broker_effect};
use super::{VmHttpDispatch, VmHttpResponse, VmHttpStatus};

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

/// Drive an outcome upload through the `broker_effect` guard: everything that
/// answers *without* recording an outcome runs first
/// ([`AgentRunOutcomeEffect::admit`]), and only an admitted upload reaches the
/// driver, which resumes the run's launch row, materialises the streams, and
/// completes the outcome.
pub(super) async fn route_agent_run_outcome_request<S: SecretStore>(
    run_id: AgentRunId,
    authenticated_session_id: SessionId,
    body: &[u8],
    service: &VmHttpAgentRunService<S>,
) -> VmHttpDispatch {
    match AgentRunOutcomeEffect::admit(run_id, authenticated_session_id, body, service) {
        AgentRunOutcomeAdmission::Answered(response) => response.into(),
        AgentRunOutcomeAdmission::Admitted(effect) => {
            broker_effect(&service.broker_state().audit, effect).await
        }
    }
}

/// The outcome of pre-flighting an upload: either an admitted effect for the
/// driver, or a response given without recording anything.
enum AgentRunOutcomeAdmission {
    Admitted(AgentRunOutcomeEffect),
    /// A foreign or unknown run, an idempotent retry, or a malformed body — none
    /// of which record an outcome.
    Answered(VmHttpResponse),
}

/// An admitted outcome upload modelled as a [`BrokeredEffect`]. The effect is
/// writing the run's retained stdout/stderr to the host filesystem; the driver
/// owns the guard across it, so those logs cannot land without the outcome row
/// that describes them (or, if the write fails, without the run's launch row
/// being left honestly unpaired).
struct AgentRunOutcomeEffect {
    run_id: AgentRunId,
    upload: VmAgentRunOutcomeUpload,
    log_root: PathBuf,
}

impl AgentRunOutcomeEffect {
    fn admit<S: SecretStore>(
        run_id: AgentRunId,
        authenticated_session_id: SessionId,
        body: &[u8],
        service: &VmHttpAgentRunService<S>,
    ) -> AgentRunOutcomeAdmission {
        let audit = &service.broker_state().audit;
        // Bind the run to the authenticated session before any lookup or write.
        // The run's owning session is fixed at request time; a session may only
        // submit an outcome for a run it owns. A run belonging to another
        // session — or one that does not exist — is reported identically as "not
        // found", so this endpoint cannot be used as an oracle for other
        // sessions' run IDs.
        match audit.get_agent_run(run_id) {
            Ok(Some(record)) if record.session_id == authenticated_session_id => {}
            Ok(_) => return AgentRunOutcomeAdmission::Answered(not_found()),
            Err(err) => {
                return AgentRunOutcomeAdmission::Answered(audit_read_failed(
                    "agent_run_lookup",
                    run_id,
                    &err,
                ));
            }
        }
        // An outcome already recorded is an idempotent retry: answer as though
        // this upload had produced it, and record nothing. This check is an
        // early-out, not the authority — it runs outside the run's claim, so a
        // concurrent upload can complete between here and `acquire`. The
        // authoritative check is `resume_effect`'s, made under the claim; this
        // one exists so a retry after completion is answered without parsing
        // (and so a malformed retry body still gets the `200` it always did).
        match audit.get_agent_run_outcome(run_id) {
            Ok(Some(_)) => return AgentRunOutcomeAdmission::Answered(ok()),
            Ok(None) => {}
            Err(err) => {
                return AgentRunOutcomeAdmission::Answered(audit_read_failed(
                    "agent_run_outcome_lookup",
                    run_id,
                    &err,
                ));
            }
        }
        let upload = match serde_json::from_slice::<VmAgentRunOutcomeUpload>(body) {
            Ok(upload) => upload,
            Err(_) => {
                return AgentRunOutcomeAdmission::Answered(VmHttpResponse::text(
                    VmHttpStatus::BadRequest,
                    "invalid outcome JSON",
                ));
            }
        };
        if upload.run_id != run_id {
            return AgentRunOutcomeAdmission::Answered(VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                "outcome run ID mismatch",
            ));
        }
        AgentRunOutcomeAdmission::Admitted(AgentRunOutcomeEffect {
            run_id,
            upload,
            log_root: service.log_root().to_path_buf(),
        })
    }
}

impl BrokeredEffect for AgentRunOutcomeEffect {
    type Table = AgentRunAuditTable;
    type Outcome = AgentRunOutcome;
    const REQUEST_AUDIT_KIND: &'static str = "agent_run_resume";
    const OUTCOME_AUDIT_KIND: &'static str = "agent_run_outcome";

    fn audit_key(&self) -> impl std::fmt::Display + '_ {
        self.run_id
    }

    /// Unreachable: [`acquire`](Self::acquire) resumes the launch row instead of
    /// beginning a new one, so the driver never asks for a request row. Building
    /// one here would be the double-insert `resume_effect` exists to prevent.
    fn request_row(&self) -> AgentRunAuditRecord {
        unreachable!("agent-run outcomes resume the launch row; they never begin one")
    }

    /// Resume the `agent_run` row minted when the run was launched, claiming the
    /// run id for the guard's lifetime.
    fn acquire(
        &self,
        audit: &Arc<AuditLog>,
    ) -> Result<RecordedRequest<AgentRunAuditTable>, AcquireFailure> {
        audit
            .resume_effect::<AgentRunAuditTable>(self.run_id)
            .map_err(|err| match err {
                // The run vanished between the ownership check and here. Same
                // answer as an unknown run: never an ID oracle.
                ResumeEffectError::NotBegun => AcquireFailure::Answered(not_found()),
                // Another upload completed this run's outcome between the
                // admission check above and this claim. That is an idempotent
                // retry — the outcome *is* recorded — so it gets the same `200`
                // a sequential retry gets, without performing the effect a
                // second time. This is the authoritative check: the one in
                // `admit` runs outside the claim and can be stale.
                ResumeEffectError::AlreadyCompleted => AcquireFailure::Answered(ok()),
                // Another upload for this run is in flight. Refuse rather than
                // return the idempotent `200`: the in-flight upload may yet
                // fail, and claiming an outcome was recorded when none was is
                // the one answer this endpoint must never give. A retry gets
                // either `200` (the outcome landed) or another `409`.
                ResumeEffectError::AlreadyClaimed => {
                    AcquireFailure::Answered(VmHttpResponse::text(
                        VmHttpStatus::Conflict,
                        "outcome upload already in flight",
                    ))
                }
                ResumeEffectError::Audit(err) => AcquireFailure::Audit(err),
            })
    }

    async fn perform(self) -> EffectCompletion<Self> {
        let AgentRunOutcomeEffect {
            upload, log_root, ..
        } = self;
        match materialize_agent_run_outcome_upload(upload, &log_root) {
            Ok(outcome) => EffectCompletion::Buffered {
                outcome,
                response: ok(),
            },
            // The upload was rejected, or its logs could not be written: there is
            // no truthful outcome for this run, so abandon rather than fabricate
            // one. This is not merely "a fabricated row is worse than none" — the
            // outcome row's primary key is the run id, so a fabricated failure
            // would consume the run's only outcome slot and permanently prevent
            // the real outcome from being recorded. An unpaired launch row is
            // exactly what a run whose outcome has not arrived looks like, and
            // the guest may retry.
            Err(response) => EffectCompletion::Abandoned(Box::new(move |guard| {
                guard.abandon();
                response.into()
            })),
        }
    }

    fn outcome_row(outcome: &AgentRunOutcome) -> AgentRunOutcomeAuditRecord {
        AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::now(),
            outcome: outcome.clone(),
        }
    }
}

fn ok() -> VmHttpResponse {
    VmHttpResponse::text(VmHttpStatus::Ok, "ok")
}

fn not_found() -> VmHttpResponse {
    VmHttpResponse::text(VmHttpStatus::NotFound, "not found")
}

fn audit_read_failed(
    kind: &'static str,
    run_id: AgentRunId,
    err: &dyn std::fmt::Display,
) -> VmHttpResponse {
    tracing::error!(
        target: AUDIT_WRITE_FAILURE_TARGET,
        kind,
        run_id = %run_id,
        error = %err,
        "audit read failed",
    );
    VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed")
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
    // Every check above has run, so the untrusted upload has been parsed into
    // something with the shape of a capture: `retained_*` are the bytes just
    // written (their hash verified against them), and `full_*` are the guest's
    // claims about the whole stream. Narrowing it with the same `to_summary`
    // the host-spawn path uses is what keeps a truncated stream meaning one
    // thing in the audit row regardless of which arm produced it.
    //
    // Deriving `truncated` from the two lengths agrees with the guest's own
    // flag, rather than replacing it: the checks above accept the upload only
    // when `truncated` implies `retained_len < byte_len` and `!truncated`
    // implies `retained_len == byte_len`, so past this point the flag and the
    // comparison are the same predicate. The comparison is the one kept because
    // it cannot disagree with the bytes on disk.
    Ok(AgentRunStreamCapture {
        path: path.to_path_buf(),
        retained_byte_len: retained_len,
        retained_sha256_hex: upload.retained_sha256_hex,
        full_byte_len: upload.byte_len,
        full_sha256_hex: upload.sha256_hex,
    }
    .to_summary())
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
                purpose: None,
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
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
                .await
                .into_buffered();

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
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
                .await
                .into_buffered();
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
                purpose: None,
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
            route_agent_run_outcome_request(run_id, attacker_session_id, &body, &service)
                .await
                .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
        // No outcome may have been written for the owner's run.
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_none());

        // The rightful owner can still submit its own outcome afterwards.
        let owner_response =
            route_agent_run_outcome_request(run_id, owner.session_id(), &body, &service)
                .await
                .into_buffered();
        assert_eq!(owner_response.status, VmHttpStatus::Ok);
    }

    /// Seed a launched run owned by `session` and return a valid upload body for
    /// it, so the tests below differ only in what they do to that upload.
    fn launched_run(
        state: &Arc<crate::server::BrokerState<Box<dyn SecretStore>>>,
        session_id: SessionId,
        run_id: AgentRunId,
    ) -> VmAgentRunOutcomeUpload {
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id,
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: None,
                purpose: None,
            })
            .unwrap();
        let empty = AgentRunStreamUpload {
            byte_len: 0,
            sha256_hex: crate::agent_run::sha256_hex(b""),
            truncated: false,
            retained_sha256_hex: crate::agent_run::sha256_hex(b""),
            retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
        };
        VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: empty.clone(),
            stderr: empty,
        }
    }

    /// Exactly one upload for a run may proceed at a time. A second, arriving
    /// while the first still holds the run's guard, is refused *before* it writes
    /// any logs — and is told so honestly, rather than given the idempotent `200`
    /// for an outcome that has not been recorded and might yet fail.
    #[tokio::test]
    async fn a_concurrent_upload_is_refused_while_one_is_in_flight() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000406".parse().unwrap();
        let upload = launched_run(&state, session.session_id(), run_id);
        let body = serde_json::to_vec(&upload).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));

        // Stand in for an upload already inside the driver: it holds the run's
        // guard, exactly as `acquire` does for the duration of `perform`.
        let in_flight = state
            .audit
            .resume_effect::<AgentRunAuditTable>(run_id)
            .expect("the run was launched and is unclaimed");

        let contended =
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
                .await
                .into_buffered();

        assert_eq!(contended.status, VmHttpStatus::Conflict);
        assert!(
            state.audit.get_agent_run_outcome(run_id).unwrap().is_none(),
            "the refused upload must not have recorded anything"
        );
        assert!(
            !temp
                .path()
                .join("agent-runs")
                .join(run_id.to_string())
                .exists(),
            "the refused upload must not have written logs either"
        );

        // Once the in-flight upload is done with the run, a retry proceeds.
        in_flight.abandon();
        let retried =
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
                .await
                .into_buffered();
        assert_eq!(retried.status, VmHttpStatus::Ok);
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_some());
    }

    /// The admission-time "already has an outcome?" check runs outside the run's
    /// claim, so it can go stale: another upload may complete between it and the
    /// claim. The upload that got the stale answer must *not* then perform the
    /// effect and discover the collision at the outcome row's primary key — the
    /// authoritative check inside `resume_effect` catches it and gives the same
    /// idempotent `200` a sequential retry gets.
    #[tokio::test]
    async fn an_upload_admitted_before_another_completed_is_answered_idempotently() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000408".parse().unwrap();
        let upload = launched_run(&state, session.session_id(), run_id);
        let temp = tempfile::tempdir().unwrap();
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));

        // Admit an upload while no outcome exists — the stale observation.
        let AgentRunOutcomeAdmission::Admitted(stale) = AgentRunOutcomeEffect::admit(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &service,
        ) else {
            panic!("a launched, unrecorded run must admit");
        };

        // ...then let another upload complete the run, exactly as a concurrent
        // request would have between the admission and the claim.
        let winner_service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("winner-runs"));
        let winner = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &winner_service,
        )
        .await
        .into_buffered();
        assert_eq!(winner.status, VmHttpStatus::Ok);

        let response = broker_effect(&state.audit, stale).await.into_buffered();

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.body, b"ok");
        assert!(
            !temp
                .path()
                .join("agent-runs")
                .join(run_id.to_string())
                .exists(),
            "the stale upload must not have performed the effect a second time"
        );
        // The winner's outcome stands, and the pair is complete.
        let recorded = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert!(
            recorded
                .outcome
                .stdout
                .path
                .starts_with(temp.path().join("winner-runs")),
            "got: {}",
            recorded.outcome.stdout.path.display()
        );
        state
            .audit
            .assert_effect_audit_pairs_complete("agent_run", "agent_run_outcome", "run_id");
    }

    /// An upload the broker cannot honestly record — a rejected stream, or logs
    /// it fails to write — must leave the run's outcome slot **free**. The
    /// outcome row is keyed by run id, so recording a fabricated failure would
    /// permanently prevent the run's real outcome from ever being recorded.
    #[tokio::test]
    async fn a_rejected_upload_leaves_the_run_free_to_report_its_real_outcome() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000407".parse().unwrap();
        let upload = launched_run(&state, session.session_id(), run_id);
        let temp = tempfile::tempdir().unwrap();

        // (a) A stream whose retained bytes contradict their hash is rejected
        // after the guard is live.
        let mut bad = upload.clone();
        bad.stdout.retained_sha256_hex = crate::agent_run::sha256_hex(b"not what was sent");
        let service =
            VmHttpAgentRunService::new(Arc::clone(&state), temp.path().join("agent-runs"));
        let rejected = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&bad).unwrap(),
            &service,
        )
        .await
        .into_buffered();
        assert_eq!(rejected.status, VmHttpStatus::BadRequest);
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_none());

        // (b) Logs that cannot be written — the log root is a regular file, so
        // the run directory cannot be created — are a host fault, and equally
        // must not consume the slot.
        let blocker = temp.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let broken = VmHttpAgentRunService::new(Arc::clone(&state), blocker.join("agent-runs"));
        let failed = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &broken,
        )
        .await
        .into_buffered();
        assert_eq!(failed.status, VmHttpStatus::InternalServerError);
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_none());

        // The run can still report its real outcome afterwards, and the pair is
        // complete.
        let recovered = route_agent_run_outcome_request(
            run_id,
            session.session_id(),
            &serde_json::to_vec(&upload).unwrap(),
            &service,
        )
        .await
        .into_buffered();
        assert_eq!(recovered.status, VmHttpStatus::Ok);
        assert!(state.audit.get_agent_run_outcome(run_id).unwrap().is_some());
        state
            .audit
            .assert_effect_audit_pairs_complete("agent_run", "agent_run_outcome", "run_id");
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
            route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
                .await
                .into_buffered();

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
                purpose: None,
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
        )
        .await
        .into_buffered();

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
        )
        .await
        .into_buffered();
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
        )
        .await
        .into_buffered();
        assert_eq!(response.status, VmHttpStatus::Ok);
        let outcome = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(outcome.outcome.stdout.byte_len, 1);
        assert_eq!(
            outcome.outcome.stdout.sha256_hex,
            crate::agent_run::sha256_hex(b"H")
        );
        // The row's `truncated` is derived from "kept less than was claimed",
        // not copied from the guest's flag — and on an accepted upload the two
        // agree, which is what lets the derivation stand in for the flag.
        assert!(outcome.outcome.stdout.truncated);
    }
}
