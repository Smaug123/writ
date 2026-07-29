//! Tests for `/v1/agent-runs/{run_id}`.
//!
//! The load-bearing one is [`the_response_carries_every_audit_field_and_no_others`]:
//! this resource exists *because* fields were unreachable, so the defect
//! it must prevent is a field silently going missing again. An
//! example-per-field test only covers the fields someone thought of, so
//! the property asserts the exact key set rather than a subset, and
//! generates each value independently so a transposition (stdout for
//! stderr, requested_at for completed_at) cannot pass by coincidence.

use super::*;
use crate::agent_run::AgentRunOutcome;
use crate::audit::{AgentRunAuditRecord, AgentRunOutcomeAuditRecord, AuditLog};
use crate::core::SessionRecord;
use crate::ui_http::{UiHttpBearerToken, serve_ui_http_request};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use proptest::prelude::*;
use std::sync::Arc;

const BEARER: &str = "agent-runs-test-bearer";

fn sha256_hex() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(b"0123456789abcdef".to_vec()),
        64..=64,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("hex digits are ASCII"))
}

/// Previews are operator-facing free text that reaches JSON verbatim,
/// so the generator leans on the characters an encoding bug would trip
/// over: quotes, backslashes, angle brackets, and non-ASCII.
fn preview() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 ]{1,40}",
        Just("say \"hello\"".to_string()),
        Just("back\\slash".to_string()),
        Just("</script>".to_string()),
        Just("naïve — ünïcode 🎉".to_string()),
    ]
}

fn stream_summary() -> impl Strategy<Value = AgentRunStreamSummary> {
    (
        "(/[a-z]{1,8}){1,3}\\.log",
        0u64..1_000_000,
        sha256_hex(),
        any::<bool>(),
    )
        .prop_map(
            |(path, byte_len, sha256_hex, truncated)| AgentRunStreamSummary {
                path: std::path::PathBuf::from(path),
                byte_len,
                sha256_hex,
                truncated,
            },
        )
}

/// One recorded run: the request row and, for some runs, the outcome.
/// Every field varies independently — including `status` against
/// `exit_code`, which the audit log does not cross-check — because this
/// resource must report what was *recorded*, not re-derive it.
fn recorded_run() -> impl Strategy<Value = (AgentRunAuditRecord, Option<AgentRunOutcomeAuditRecord>)>
{
    (
        0i64..4_000_000_000_000,
        proptest::sample::select(vec![AgentKind::Claude, AgentKind::Codex]),
        (0u64..1_000_000, sha256_hex(), preview()),
        proptest::option::of("[a-zA-Z0-9_-]{1,64}"),
        // Anchored at both ends so no purpose starts or ends with a
        // space, which `RunPurpose::try_new` refuses.
        proptest::option::of("[a-zA-Z0-9:#-]([a-zA-Z0-9 :#-]{0,38}[a-zA-Z0-9:#-])?"),
        proptest::option::of((
            0i64..4_000_000_000_000,
            any::<i32>(),
            prop_oneof![
                Just(AgentRunTerminalStatus::Succeeded),
                Just(AgentRunTerminalStatus::Failed)
            ],
            stream_summary(),
            stream_summary(),
        )),
    )
        .prop_map(
            |(
                requested_ms,
                agent_kind,
                (prompt_bytes, prompt_sha, prompt_preview),
                correlation,
                purpose,
                outcome,
            )| {
                let run_id = AgentRunId::new();
                let request = AgentRunAuditRecord {
                    run_id,
                    session_id: SessionId::new(),
                    requested_at: UnixMillis::from_millis(requested_ms),
                    agent_kind,
                    prompt: AgentPromptSummary {
                        byte_len: prompt_bytes,
                        sha256_hex: prompt_sha,
                        redacted_preview: prompt_preview,
                    },
                    correlation_id: correlation
                        .map(|c| CorrelationId::try_new(c).expect("generator obeys the class")),
                    purpose: purpose
                        .map(|p| RunPurpose::try_new(p).expect("generator obeys the class")),
                };
                let outcome = outcome.map(|(completed_ms, exit_code, status, stdout, stderr)| {
                    AgentRunOutcomeAuditRecord {
                        completed_at: UnixMillis::from_millis(completed_ms),
                        outcome: AgentRunOutcome {
                            run_id,
                            status,
                            exit_code,
                            stdout,
                            stderr,
                        },
                    }
                });
                (request, outcome)
            },
        )
}

/// Seed the FK chain and hand back a service reading the same log.
fn service_with(
    request: &AgentRunAuditRecord,
    outcome: Option<&AgentRunOutcomeAuditRecord>,
) -> UiHttpService {
    let audit = Arc::new(AuditLog::open_in_memory().expect("in-memory audit log"));
    audit
        .open_session(&SessionRecord {
            session_id: request.session_id,
            label: Some("agent-runs test".into()),
            agent_kind: Some(request.agent_kind),
            agent_model: Some("claude-opus-5".into()),
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .expect("session opens");
    audit.record_agent_run(request).expect("run row records");
    if let Some(o) = outcome {
        audit
            .record_agent_run_outcome(o)
            .expect("outcome row records");
    }
    UiHttpService::new(
        audit,
        None,
        UiHttpBearerToken::new(BEARER).expect("a valid bearer"),
    )
}

fn empty_request(method: &str, target: &str) -> http::Request<Full<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Full::new(Bytes::new()))
        .expect("a valid request")
}

async fn get(service: &UiHttpService, target: &str) -> (u16, serde_json::Value) {
    let response = serve_ui_http_request(service, empty_request("GET", target)).await;
    let status = response.status().as_u16();
    let bytes = response
        .into_parts()
        .1
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "response is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

proptest! {
    /// The exact key set, and every value, for any recorded run.
    ///
    /// Asserting the key set *exactly* rather than by subset is the
    /// point: a subset check passes when a field is dropped, which is
    /// the failure this resource exists to prevent.
    #[test]
    fn the_response_carries_every_audit_field_and_no_others(
        (request, outcome) in recorded_run()
    ) {
        let service = service_with(&request, outcome.as_ref());
        let target = format!("/v1/agent-runs/{}", request.run_id);
        let (status, body) = rt().block_on(get(&service, &target));

        prop_assert_eq!(status, 200);
        let obj = body.as_object().expect("a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        prop_assert_eq!(
            keys,
            vec![
                "agent_kind",
                "correlation_id",
                "outcome",
                "prompt",
                "purpose",
                "requested_at",
                "run_id",
                "session_id",
            ]
        );

        let expected_run_id = request.run_id.to_string();
        let expected_session_id = request.session_id.to_string();
        prop_assert_eq!(obj["run_id"].as_str(), Some(expected_run_id.as_str()));
        prop_assert_eq!(obj["session_id"].as_str(), Some(expected_session_id.as_str()));
        prop_assert_eq!(obj["requested_at"].as_i64(), Some(request.requested_at.as_millis()));
        prop_assert_eq!(obj["agent_kind"].as_str(), Some(request.agent_kind.as_str()));
        prop_assert_eq!(
            obj["purpose"].as_str(),
            request.purpose.as_ref().map(|p| p.as_str())
        );
        prop_assert_eq!(
            obj["correlation_id"].as_str(),
            request.correlation_id.as_ref().map(|c| c.as_str())
        );

        let prompt = obj["prompt"].as_object().expect("prompt is an object");
        let mut prompt_keys: Vec<&str> = prompt.keys().map(String::as_str).collect();
        prompt_keys.sort_unstable();
        prop_assert_eq!(prompt_keys, vec!["byte_len", "redacted_preview", "sha256_hex"]);
        prop_assert_eq!(prompt["byte_len"].as_u64(), Some(request.prompt.byte_len));
        prop_assert_eq!(prompt["sha256_hex"].as_str(), Some(request.prompt.sha256_hex.as_str()));
        prop_assert_eq!(
            prompt["redacted_preview"].as_str(),
            Some(request.prompt.redacted_preview.as_str())
        );

        match outcome {
            None => prop_assert!(obj["outcome"].is_null()),
            Some(o) => {
                let got = obj["outcome"].as_object().expect("outcome is an object");
                let mut outcome_keys: Vec<&str> = got.keys().map(String::as_str).collect();
                outcome_keys.sort_unstable();
                prop_assert_eq!(
                    outcome_keys,
                    vec!["completed_at", "exit_code", "status", "stderr", "stdout"]
                );
                prop_assert_eq!(got["completed_at"].as_i64(), Some(o.completed_at.as_millis()));
                prop_assert_eq!(got["exit_code"].as_i64(), Some(i64::from(o.outcome.exit_code)));
                let expected_status = match o.outcome.status {
                    AgentRunTerminalStatus::Succeeded => "succeeded",
                    AgentRunTerminalStatus::Failed => "failed",
                };
                prop_assert_eq!(got["status"].as_str(), Some(expected_status));
                // Checked separately rather than through a helper, so a
                // handler that reported stdout for both fields fails here
                // instead of agreeing with itself.
                assert_stream(&got["stdout"], &o.outcome.stdout)?;
                assert_stream(&got["stderr"], &o.outcome.stderr)?;
            }
        }
    }
}

fn assert_stream(
    got: &serde_json::Value,
    expected: &AgentRunStreamSummary,
) -> Result<(), TestCaseError> {
    let got = got.as_object().expect("a stream object");
    let mut keys: Vec<&str> = got.keys().map(String::as_str).collect();
    keys.sort_unstable();
    prop_assert_eq!(keys, vec!["byte_len", "path", "sha256_hex", "truncated"]);
    prop_assert_eq!(
        got["path"].as_str(),
        Some(expected.path.to_str().expect("a UTF-8 path"))
    );
    prop_assert_eq!(got["byte_len"].as_u64(), Some(expected.byte_len));
    prop_assert_eq!(
        got["sha256_hex"].as_str(),
        Some(expected.sha256_hex.as_str())
    );
    prop_assert_eq!(got["truncated"].as_bool(), Some(expected.truncated));
    Ok(())
}

/// The two streams are reported the way round they were recorded.
///
/// The property above already covers this, but only because it
/// generates the two summaries independently; this pins the minimal
/// witness as a named, deterministic case. The two differ *only* in
/// their digest, which is the shape a real run produces — both streams
/// of one run share a directory and are usually both untruncated — so
/// a handler that read `stdout` twice would agree with itself on every
/// other field.
#[tokio::test]
async fn stdout_and_stderr_are_not_transposed() {
    let run_id = AgentRunId::new();
    let request = AgentRunAuditRecord {
        run_id,
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("x").summary(),
        correlation_id: None,
        purpose: None,
    };
    let stream = |digit: char| AgentRunStreamSummary {
        path: std::path::PathBuf::from("/logs/run.log"),
        byte_len: 0,
        sha256_hex: std::iter::repeat_n(digit, 64).collect(),
        truncated: false,
    };
    let outcome = AgentRunOutcomeAuditRecord {
        completed_at: UnixMillis::from_millis(1_700_000_100),
        outcome: AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: stream('a'),
            stderr: stream('b'),
        },
    };
    let service = service_with(&request, Some(&outcome));
    let (status, body) = get(&service, &format!("/v1/agent-runs/{run_id}")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["outcome"]["stdout"]["sha256_hex"].as_str(),
        Some("a".repeat(64).as_str()),
        "body: {body}"
    );
    assert_eq!(
        body["outcome"]["stderr"]["sha256_hex"].as_str(),
        Some("b".repeat(64).as_str()),
        "body: {body}"
    );
}

/// A run with no outcome row reports `"outcome": null` rather than
/// omitting the key or 404ing: an in-flight run is exactly what an
/// operator opening this resource most wants to look at.
#[tokio::test]
async fn an_in_flight_run_reports_a_null_outcome() {
    let request = AgentRunAuditRecord {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("in flight").summary(),
        correlation_id: None,
        purpose: None,
    };
    let service = service_with(&request, None);
    let target = format!("/v1/agent-runs/{}", request.run_id);
    let (status, body) = get(&service, &target).await;
    assert_eq!(status, 200);
    assert!(
        body.as_object().expect("an object").contains_key("outcome"),
        "the key must be present even when null: {body}"
    );
    assert!(body["outcome"].is_null(), "body: {body}");
}

/// An id that is not a UUID is refused as malformed, and the response
/// says which id it could not parse — 404 rather than 400 to match the
/// session routes, which treat "cannot name it" and "have not got it"
/// as the same answer to the client.
#[tokio::test]
async fn a_malformed_run_id_is_refused_by_name() {
    let request = AgentRunAuditRecord {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("x").summary(),
        correlation_id: None,
        purpose: None,
    };
    let service = service_with(&request, None);
    let (status, body) = get(&service, "/v1/agent-runs/not-a-uuid").await;
    assert_eq!(status, 404);
    assert_eq!(body["error"].as_str(), Some("malformed_run_id"));
    assert_eq!(body["run_id"].as_str(), Some("not-a-uuid"));
    assert!(
        body.get("session_id").is_none(),
        "a run error must not carry a session id: {body}"
    );
}

/// A well-formed id with no row is `unknown_run`, distinct from
/// `malformed_run_id`. The distinction is what tells an operator
/// whether to fix their command or go looking for a lost run.
#[tokio::test]
async fn an_unknown_run_is_distinguished_from_a_malformed_one() {
    let request = AgentRunAuditRecord {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("x").summary(),
        correlation_id: None,
        purpose: None,
    };
    let service = service_with(&request, None);
    let absent = AgentRunId::new();
    let (status, body) = get(&service, &format!("/v1/agent-runs/{absent}")).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"].as_str(), Some("unknown_run"));
    assert_eq!(body["run_id"].as_str(), Some(absent.to_string().as_str()));
}

/// The resource is read-only; a write verb is refused with the allowed
/// set rather than silently treated as a GET.
#[tokio::test]
async fn only_get_is_allowed() {
    let request = AgentRunAuditRecord {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("x").summary(),
        correlation_id: None,
        purpose: None,
    };
    let service = service_with(&request, None);
    let target = format!("/v1/agent-runs/{}", request.run_id);
    let response = serve_ui_http_request(&service, empty_request("DELETE", &target)).await;
    assert_eq!(response.status().as_u16(), 405);
}

/// A nested path is not found rather than being parsed as a run id with
/// the tail ignored — the same rule the agent-VM routes apply, and the
/// reason neither route needs to worry about a crafted trailing segment.
#[tokio::test]
async fn a_nested_path_is_not_found() {
    let request = AgentRunAuditRecord {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        requested_at: UnixMillis::from_millis(1_700_000_050),
        agent_kind: AgentKind::Claude,
        prompt: crate::agent_run::AgentPrompt::new("x").summary(),
        correlation_id: None,
        purpose: None,
    };
    let service = service_with(&request, None);
    let target = format!("/v1/agent-runs/{}/streams", request.run_id);
    let (status, body) = get(&service, &target).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"].as_str(), Some("not_found"));

    let (status, body) = get(&service, "/v1/agent-runs/").await;
    assert_eq!(status, 404);
    assert_eq!(body["error"].as_str(), Some("not_found"));
}
