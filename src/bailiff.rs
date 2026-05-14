//! Orchestrator-side workflow helpers. Lives outside the broker so the
//! plan/review/execute prompt composition (and the workflow vocabulary
//! it carries) does not leak into the capability-broker code.
//!
//! See `docs/plans/2026-05-14-bailiff-split.md` for the broader split;
//! the pure-composition core is the slice-1 lift from `agent_plan.rs`,
//! and `fetch_effective_prompt` is the slice-2 lift of the VM-side
//! dispatch wrapper from `writ-vm.rs`. The broker still persists
//! [`PlanBody`] and [`Stage`]; only the *interpretation* (decide
//! whether to fetch the plan, then splice it into the agent's
//! effective prompt) lives here.

use crate::agent_plan::{PlanBody, Stage};
use crate::agent_run::{AgentPrompt, AgentPromptError};

/// Separator the implementer's effective prompt uses between the
/// feature-request prompt and the approved plan body. See
/// [`compose_implementer_prompt`].
pub const PLAN_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Approved plan\n\n";

/// Separator the reviewer's effective prompt uses between the
/// operator-supplied reviewer instructions and the plan body under
/// evaluation. Distinct from [`PLAN_PROMPT_SEPARATOR`] because the
/// reviewer is judging the plan, not executing against an approved
/// one — `# Proposed plan` makes that frame explicit so an LLM reading
/// the combined prompt cannot mistake the artifact's status. See
/// [`compose_reviewer_prompt`].
pub const REVIEWER_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Proposed plan\n\n";

/// Build the implementer's effective prompt from the original
/// feature-request prompt that produced the plan and the accepted plan
/// body. Per §"Implementer prompt construction" of
/// `docs/plans/2026-05-11-agent-plans.md`, reviewer feedback stays
/// *out* of the composed prompt by default: it's for the decision, not
/// for execution.
///
/// The two inputs are joined by [`PLAN_PROMPT_SEPARATOR`], which adds
/// a clear visual boundary (`---` plus an `# Approved plan` heading)
/// so an LLM reading the combined prompt cannot mistake one segment
/// for the other. Returns [`AgentPromptError`] iff the combined byte
/// length exceeds [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`].
pub fn compose_implementer_prompt(
    feature_prompt: &AgentPrompt,
    plan_body: &PlanBody,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined = String::with_capacity(
        feature_prompt.as_str().len() + PLAN_PROMPT_SEPARATOR.len() + plan_body.as_str().len(),
    );
    combined.push_str(feature_prompt.as_str());
    combined.push_str(PLAN_PROMPT_SEPARATOR);
    combined.push_str(plan_body.as_str());
    AgentPrompt::try_new(combined)
}

/// Build the reviewer's effective prompt from the operator-supplied
/// reviewer instructions and the plan body the reviewer is voting on.
/// Mirrors [`compose_implementer_prompt`] but uses
/// [`REVIEWER_PROMPT_SEPARATOR`] (`# Proposed plan`) because the plan
/// has not been accepted at the point the reviewer reads it — the
/// reviewer's job is to produce the verdict that drives the accept /
/// request_changes / reject decision (see
/// `docs/plans/2026-05-11-agent-plans.md` §"Conceptual model").
/// Returns [`AgentPromptError`] iff the combined byte length exceeds
/// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`].
pub fn compose_reviewer_prompt(
    reviewer_prompt: &AgentPrompt,
    plan_body: &PlanBody,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined = String::with_capacity(
        reviewer_prompt.as_str().len() + REVIEWER_PROMPT_SEPARATOR.len() + plan_body.as_str().len(),
    );
    combined.push_str(reviewer_prompt.as_str());
    combined.push_str(REVIEWER_PROMPT_SEPARATOR);
    combined.push_str(plan_body.as_str());
    AgentPrompt::try_new(combined)
}

/// Returns `true` iff [`compose_effective_prompt`] would consume a
/// plan body for runs in this `stage`. The VM-side wrapper consults
/// this to decide whether to call `GET /v1/plans/<id>` before
/// composing the prompt: fetching only when the dispatcher will use
/// the result keeps the two in sync (a previous regression — caught
/// by codex on PR #80 — let the wrapper skip the fetch for review
/// runs and silently bypass the reviewer composition arm).
pub fn stage_consumes_plan_body(stage: Stage) -> bool {
    match stage {
        Stage::Plan => false,
        Stage::Review | Stage::Execute => true,
    }
}

/// Returns the prompt the VM-side wrapper should feed the LLM, given
/// the run's stage and the plan body (when one was fetched).
/// `(Stage::Execute, Some(body))` composes via
/// [`compose_implementer_prompt`]; `(Stage::Review, Some(body))`
/// composes via [`compose_reviewer_prompt`]; every other combination
/// passes the caller's prompt through unchanged. `Stage::Plan` never
/// reads a plan, and `Stage::Review` without a body only arises if
/// `validate_stage_read_plan_binding` was bypassed — passthrough is
/// the conservative answer there.
///
/// `plan_body` is `Some` exactly when the broker handed back a
/// `read_plan_id` *and* the writ-vm wrapper successfully fetched the
/// plan body for it. The wrapper decides whether to fetch via
/// [`stage_consumes_plan_body`] — keep the two in step.
pub fn compose_effective_prompt(
    feature_prompt: &AgentPrompt,
    stage: Stage,
    plan_body: Option<&PlanBody>,
) -> Result<AgentPrompt, AgentPromptError> {
    match (stage, plan_body) {
        (Stage::Execute, Some(body)) => compose_implementer_prompt(feature_prompt, body),
        (Stage::Review, Some(body)) => compose_reviewer_prompt(feature_prompt, body),
        _ => Ok(feature_prompt.clone()),
    }
}

/// Error returned by [`fetch_effective_prompt`]. Either the plan fetch
/// failed or the composition overflowed the per-prompt byte limit.
#[cfg(feature = "vm-client")]
#[derive(Debug, thiserror::Error)]
pub enum FetchEffectivePromptError {
    #[error("fetching plan from broker failed: {0}")]
    Fetch(#[from] crate::vm_client::VmClientError),
    #[error("composing effective prompt failed: {0}")]
    Compose(#[from] AgentPromptError),
}

/// Fetch the plan body iff the dispatcher would consume one for this
/// stage, then compose the effective prompt the VM-side wrapper feeds
/// the LLM. The plan is fetched only when both conditions hold —
/// `read_plan_id` is `Some` *and* [`stage_consumes_plan_body`] returns
/// `true` — so a stage that would discard the body via passthrough
/// does not pay an HTTP round-trip just to drop the result.
///
/// Bailiff (and not the broker) is the right home for this dispatch:
/// the wrapper calls into the orchestrator to splice the prompt;
/// today that splice is a function call into this crate, and when
/// bailiff is a separate process it becomes a local-socket call. The
/// signature stays the same either way.
#[cfg(feature = "vm-client")]
pub async fn fetch_effective_prompt(
    config: &crate::vm_client::VmClientConfig,
    feature_prompt: &AgentPrompt,
    stage: Stage,
    read_plan_id: Option<crate::agent_plan::PlanId>,
) -> Result<AgentPrompt, FetchEffectivePromptError> {
    let plan_view = match read_plan_id {
        Some(plan_id) if stage_consumes_plan_body(stage) => {
            Some(crate::vm_client::fetch_plan(config, plan_id).await?)
        }
        _ => None,
    };
    let effective =
        compose_effective_prompt(feature_prompt, stage, plan_view.as_ref().map(|p| &p.body))?;
    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_implementer_prompt_concatenates_with_separator() {
        let feature = AgentPrompt::new("Fix the foo widget.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();
        let combined = compose_implementer_prompt(&feature, &plan).unwrap();
        let expected =
            format!("Fix the foo widget.{PLAN_PROMPT_SEPARATOR}# Plan\n\nReplace bar with baz.",);
        assert_eq!(combined.as_str(), expected);
        // Both inputs survive as substrings, separated by the marker.
        assert!(combined.as_str().contains(feature.as_str()));
        assert!(combined.as_str().contains(plan.as_str()));
        assert!(combined.as_str().contains(PLAN_PROMPT_SEPARATOR));
    }

    #[test]
    fn compose_implementer_prompt_errors_when_combined_exceeds_agent_prompt_limit() {
        // Feature prompt at the AgentPrompt limit, plus a non-empty plan
        // body and the separator, must overflow.
        let feature = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        let err = compose_implementer_prompt(&feature, &plan).unwrap_err();
        // AgentPromptError formats as "agent prompt is N bytes, ...".
        let msg = err.to_string();
        assert!(msg.contains("exceeding"), "{msg}");
    }

    #[test]
    fn compose_reviewer_prompt_concatenates_with_separator() {
        let reviewer = AgentPrompt::new("Evaluate the plan against the feature request.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();
        let combined = compose_reviewer_prompt(&reviewer, &plan).unwrap();
        let expected = format!(
            "Evaluate the plan against the feature request.{REVIEWER_PROMPT_SEPARATOR}# Plan\n\nReplace bar with baz.",
        );
        assert_eq!(combined.as_str(), expected);
        assert!(combined.as_str().contains(reviewer.as_str()));
        assert!(combined.as_str().contains(plan.as_str()));
        assert!(combined.as_str().contains(REVIEWER_PROMPT_SEPARATOR));
        // The reviewer separator must not lie about the plan's status.
        // The implementer's `# Approved plan` heading would mislead a
        // reviewer LLM; pin the separators apart so a future rewording
        // can't silently equate them.
        assert!(!combined.as_str().contains(PLAN_PROMPT_SEPARATOR));
    }

    #[test]
    fn compose_reviewer_prompt_errors_when_combined_exceeds_agent_prompt_limit() {
        let reviewer = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        let err = compose_reviewer_prompt(&reviewer, &plan).unwrap_err();
        assert!(err.to_string().contains("exceeding"), "{err}");
    }

    #[test]
    fn compose_effective_prompt_composes_for_execute_and_review_with_plan_body() {
        let feature = AgentPrompt::new("Fix the foo widget.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();

        // Execute + Some(plan) — composes via compose_implementer_prompt.
        let composed_execute =
            compose_effective_prompt(&feature, Stage::Execute, Some(&plan)).unwrap();
        let expected_execute = compose_implementer_prompt(&feature, &plan).unwrap();
        assert_eq!(composed_execute.as_str(), expected_execute.as_str());
        assert!(composed_execute.as_str().contains(PLAN_PROMPT_SEPARATOR));

        // Review + Some(plan) — composes via compose_reviewer_prompt.
        let composed_review =
            compose_effective_prompt(&feature, Stage::Review, Some(&plan)).unwrap();
        let expected_review = compose_reviewer_prompt(&feature, &plan).unwrap();
        assert_eq!(composed_review.as_str(), expected_review.as_str());
        assert!(composed_review.as_str().contains(REVIEWER_PROMPT_SEPARATOR));

        // The two separators must not collide: an implementer's prompt
        // must not be mistakable for a reviewer's prompt and vice
        // versa, because the LLM's reading of the plan depends on which
        // role it has been told it is performing.
        assert!(
            !composed_execute
                .as_str()
                .contains(REVIEWER_PROMPT_SEPARATOR)
        );
        assert!(!composed_review.as_str().contains(PLAN_PROMPT_SEPARATOR));

        // Every remaining (stage, plan_body) pair passes the prompt
        // through unchanged. Plan-stage never carries a plan body and
        // Review-without-a-body is rejected at start time by
        // `validate_stage_read_plan_binding`; passthrough is defensive.
        for (stage, body) in [
            (Stage::Plan, None),
            (Stage::Plan, Some(&plan)),
            (Stage::Review, None),
            (Stage::Execute, None),
        ] {
            let result = compose_effective_prompt(&feature, stage, body).unwrap();
            assert_eq!(
                result.as_str(),
                feature.as_str(),
                "stage={stage:?} body_is_some={}: expected passthrough",
                body.is_some(),
            );
        }
    }

    #[test]
    fn compose_effective_prompt_errors_when_composition_exceeds_limit() {
        let feature = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        for stage in [Stage::Execute, Stage::Review] {
            let err = compose_effective_prompt(&feature, stage, Some(&plan)).unwrap_err();
            assert!(
                err.to_string().contains("exceeding"),
                "stage={stage:?}: {err}"
            );
        }
    }

    /// The wrapper-side fetch predicate
    /// ([`stage_consumes_plan_body`]) must agree with the
    /// dispatcher's match in [`compose_effective_prompt`]: a stage
    /// consumes a plan body iff handing the dispatcher a body for
    /// that stage produces a different prompt than passthrough.
    /// Pins them together so the regression caught on PR #80 — where
    /// the wrapper skipped the fetch for review-stage and the
    /// dispatcher's new arm was unreachable — cannot recur.
    #[test]
    fn stage_consumes_plan_body_agrees_with_compose_effective_prompt() {
        let feature = AgentPrompt::new("feature prompt");
        let plan = PlanBody::try_new("plan body").unwrap();
        for stage in [Stage::Plan, Stage::Review, Stage::Execute] {
            let composed = compose_effective_prompt(&feature, stage, Some(&plan)).unwrap();
            let consumed = composed.as_str() != feature.as_str();
            assert_eq!(consumed, stage_consumes_plan_body(stage), "stage={stage:?}",);
        }
    }

    #[cfg(feature = "vm-client")]
    mod fetch {
        use super::*;
        use crate::agent_plan::{PlanId, PlanView};
        use crate::agent_run::AgentRunId;
        use crate::vm_client::{VmClientConfig, VmClientError};
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// Minimal single-shot HTTP responder for testing the fetch
        /// dispatch. Mirrors `vm_client::tests::serve_once` (kept private
        /// to that module) — duplicated here because integration of
        /// bailiff's dispatch with the broker's HTTP surface is what we
        /// want to pin without crossing module test-visibility.
        async fn serve_once(response: String) -> (String, Arc<Mutex<u32>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(Mutex::new(0u32));
            let hits_task = Arc::clone(&hits);
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                *hits_task.lock().unwrap() += 1;
                // Accumulate across reads: the OS is free to split the
                // request header terminator across reads, and scanning
                // only the current chunk would deadlock with the
                // reqwest client waiting on a response we never send.
                let mut request = Vec::new();
                let mut buf = [0u8; 256];
                while let Ok(read) = stream.read(&mut buf).await {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                stream.write_all(response.as_bytes()).await.ok();
            });
            (format!("http://{addr}/"), hits)
        }

        fn ok_plan_view_response(plan_id: PlanId, body: &PlanBody) -> String {
            let view = PlanView {
                plan_id,
                body: body.clone(),
                originating_run_id: AgentRunId::new(),
                decision: None,
            };
            let json = serde_json::to_vec(&view).unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                String::from_utf8(json).unwrap(),
            )
        }

        /// When `stage_consumes_plan_body` is `true` *and* `read_plan_id`
        /// is `Some`, the dispatcher fetches the plan and composes the
        /// effective prompt. Pin both the request *and* the resulting
        /// composition so a regression that drops one half doesn't slip
        /// through.
        #[tokio::test]
        async fn fetches_and_composes_when_stage_consumes_and_plan_id_present() {
            let feature = AgentPrompt::new("Fix the foo widget.");
            let body = PlanBody::try_new("# Plan\n\nDo a thing.").unwrap();
            let plan_id = PlanId::new();
            let (broker_url, hits) = serve_once(ok_plan_view_response(plan_id, &body)).await;
            let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

            let effective =
                fetch_effective_prompt(&config, &feature, Stage::Execute, Some(plan_id))
                    .await
                    .unwrap();

            assert_eq!(*hits.lock().unwrap(), 1, "broker should have been hit once");
            let expected = compose_implementer_prompt(&feature, &body).unwrap();
            assert_eq!(effective.as_str(), expected.as_str());
        }

        /// Passthrough arms must not pay an HTTP round-trip just to
        /// drop the result. Point the client at a port nothing is
        /// listening on: an accidental fetch surfaces as a connection
        /// error, so success ≡ "no fetch was attempted." Covers every
        /// `(stage, read_plan_id)` pair for which the dispatcher
        /// passes through.
        #[tokio::test]
        async fn skips_fetch_for_every_passthrough_pair() {
            let feature = AgentPrompt::new("Fix the foo widget.");
            let plan_id = PlanId::new();
            // Bind+drop to grab a port the OS won't reassign before the
            // attempt; the connect must then fail fast.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let config = VmClientConfig::new(format!("http://{addr}/"), "writ-vm-secret").unwrap();

            for (stage, read_plan_id, label) in [
                (Stage::Plan, None, "plan/none"),
                (Stage::Plan, Some(plan_id), "plan/some"),
                (Stage::Review, None, "review/none"),
                (Stage::Execute, None, "execute/none"),
            ] {
                let effective = fetch_effective_prompt(&config, &feature, stage, read_plan_id)
                    .await
                    .unwrap_or_else(|err| panic!("{label}: expected passthrough but got {err}"));
                assert_eq!(
                    effective.as_str(),
                    feature.as_str(),
                    "{label}: expected passthrough"
                );
            }
        }

        /// Broker HTTP failures surface as
        /// `FetchEffectivePromptError::Fetch`. Pin the variant so a
        /// future restructure doesn't accidentally collapse fetch and
        /// compose errors into one case.
        #[tokio::test]
        async fn fetch_errors_surface_as_fetch_variant() {
            let feature = AgentPrompt::new("Fix the foo widget.");
            let plan_id = PlanId::new();
            let (broker_url, _hits) = serve_once(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
                    .to_owned(),
            )
            .await;
            let config = VmClientConfig::new(broker_url, "writ-vm-secret").unwrap();

            let err = fetch_effective_prompt(&config, &feature, Stage::Execute, Some(plan_id))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    FetchEffectivePromptError::Fetch(VmClientError::BrokerHttp { status: 403, .. })
                ),
                "unexpected error: {err}"
            );
        }
    }
}
